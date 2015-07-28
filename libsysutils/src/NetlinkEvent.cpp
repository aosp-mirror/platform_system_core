/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "NetlinkEvent"
#include <cutils/log.h>

#include <sysutils/NetlinkEvent.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <net/if.h>

#include <linux/if.h>
#include <linux/if_addr.h>
#include <linux/if_link.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_log.h>
#include <linux/netfilter_ipv4/ipt_ULOG.h>

/* From kernel's net/netfilter/xt_quota2.c */
const int LOCAL_QLOG_NL_EVENT = 112;
const int LOCAL_NFLOG_PACKET = NFNL_SUBSYS_ULOG << 8 | NFULNL_MSG_PACKET;

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <netlink/attr.h>
#include <netlink/genl/genl.h>
#include <netlink/handlers.h>
#include <netlink/msg.h>

NetlinkEvent::NetlinkEvent() {
    mAction = Action::kUnknown;
    memset(mParams, 0, sizeof(mParams));
    mPath = NULL;
    mSubsystem = NULL;
}

NetlinkEvent::~NetlinkEvent() {
    int i;
    if (mPath)
        free(mPath);
    if (mSubsystem)
        free(mSubsystem);
    for (i = 0; i < NL_PARAMS_MAX; i++) {
        if (!mParams[i])
            break;
        free(mParams[i]);
    }
}

void NetlinkEvent::dump() {
    int i;

    for (i = 0; i < NL_PARAMS_MAX; i++) {
        if (!mParams[i])
            break;
        SLOGD("NL param '%s'\n", mParams[i]);
    }
}

/*
 * Returns the message name for a message in the NETLINK_ROUTE family, or NULL
 * if parsing that message is not supported.
 */
static const char *rtMessageName(int type) {
#define NL_EVENT_RTM_NAME(rtm) case rtm: return #rtm;
    switch (type) {
        NL_EVENT_RTM_NAME(RTM_NEWLINK);
        NL_EVENT_RTM_NAME(RTM_DELLINK);
        NL_EVENT_RTM_NAME(RTM_NEWADDR);
        NL_EVENT_RTM_NAME(RTM_DELADDR);
        NL_EVENT_RTM_NAME(RTM_NEWROUTE);
        NL_EVENT_RTM_NAME(RTM_DELROUTE);
        NL_EVENT_RTM_NAME(RTM_NEWNDUSEROPT);
        NL_EVENT_RTM_NAME(LOCAL_QLOG_NL_EVENT);
        NL_EVENT_RTM_NAME(LOCAL_NFLOG_PACKET);
        default:
            return NULL;
    }
#undef NL_EVENT_RTM_NAME
}

/*
 * Checks that a binary NETLINK_ROUTE message is long enough for a payload of
 * size bytes.
 */
static bool checkRtNetlinkLength(const struct nlmsghdr *nh, size_t size) {
    if (nh->nlmsg_len < NLMSG_LENGTH(size)) {
        SLOGE("Got a short %s message\n", rtMessageName(nh->nlmsg_type));
        return false;
    }
    return true;
}

/*
 * Utility function to log errors.
 */
static bool maybeLogDuplicateAttribute(bool isDup,
                                       const char *attributeName,
                                       const char *messageName) {
    if (isDup) {
        SLOGE("Multiple %s attributes in %s, ignoring\n", attributeName, messageName);
        return true;
    }
    return false;
}

/*
 * Parse a RTM_NEWLINK message.
 */
bool NetlinkEvent::parseIfInfoMessage(const struct nlmsghdr *nh) {
    struct ifinfomsg *ifi = (struct ifinfomsg *) NLMSG_DATA(nh);
    if (!checkRtNetlinkLength(nh, sizeof(*ifi)))
        return false;

    if ((ifi->ifi_flags & IFF_LOOPBACK) != 0) {
        return false;
    }

    int len = IFLA_PAYLOAD(nh);
    struct rtattr *rta;
    for (rta = IFLA_RTA(ifi); RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
        switch(rta->rta_type) {
            case IFLA_IFNAME:
                asprintf(&mParams[0], "INTERFACE=%s", (char *) RTA_DATA(rta));
                mAction = (ifi->ifi_flags & IFF_LOWER_UP) ? Action::kLinkUp :
                                                            Action::kLinkDown;
                mSubsystem = strdup("net");
                return true;
        }
    }

    return false;
}

/*
 * Parse a RTM_NEWADDR or RTM_DELADDR message.
 */
bool NetlinkEvent::parseIfAddrMessage(const struct nlmsghdr *nh) {
    struct ifaddrmsg *ifaddr = (struct ifaddrmsg *) NLMSG_DATA(nh);
    struct ifa_cacheinfo *cacheinfo = NULL;
    char addrstr[INET6_ADDRSTRLEN] = "";
    char ifname[IFNAMSIZ];

    if (!checkRtNetlinkLength(nh, sizeof(*ifaddr)))
        return false;

    // Sanity check.
    int type = nh->nlmsg_type;
    if (type != RTM_NEWADDR && type != RTM_DELADDR) {
        SLOGE("parseIfAddrMessage on incorrect message type 0x%x\n", type);
        return false;
    }

    // For log messages.
    const char *msgtype = rtMessageName(type);

    struct rtattr *rta;
    int len = IFA_PAYLOAD(nh);
    for (rta = IFA_RTA(ifaddr); RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
        if (rta->rta_type == IFA_ADDRESS) {
            // Only look at the first address, because we only support notifying
            // one change at a time.
            if (maybeLogDuplicateAttribute(*addrstr != '\0', "IFA_ADDRESS", msgtype))
                continue;

            // Convert the IP address to a string.
            if (ifaddr->ifa_family == AF_INET) {
                struct in_addr *addr4 = (struct in_addr *) RTA_DATA(rta);
                if (RTA_PAYLOAD(rta) < sizeof(*addr4)) {
                    SLOGE("Short IPv4 address (%zu bytes) in %s",
                          RTA_PAYLOAD(rta), msgtype);
                    continue;
                }
                inet_ntop(AF_INET, addr4, addrstr, sizeof(addrstr));
            } else if (ifaddr->ifa_family == AF_INET6) {
                struct in6_addr *addr6 = (struct in6_addr *) RTA_DATA(rta);
                if (RTA_PAYLOAD(rta) < sizeof(*addr6)) {
                    SLOGE("Short IPv6 address (%zu bytes) in %s",
                          RTA_PAYLOAD(rta), msgtype);
                    continue;
                }
                inet_ntop(AF_INET6, addr6, addrstr, sizeof(addrstr));
            } else {
                SLOGE("Unknown address family %d\n", ifaddr->ifa_family);
                continue;
            }

            // Find the interface name.
            if (!if_indextoname(ifaddr->ifa_index, ifname)) {
                SLOGE("Unknown ifindex %d in %s", ifaddr->ifa_index, msgtype);
                return false;
            }

        } else if (rta->rta_type == IFA_CACHEINFO) {
            // Address lifetime information.
            if (maybeLogDuplicateAttribute(cacheinfo, "IFA_CACHEINFO", msgtype))
                continue;

            if (RTA_PAYLOAD(rta) < sizeof(*cacheinfo)) {
                SLOGE("Short IFA_CACHEINFO (%zu vs. %zu bytes) in %s",
                      RTA_PAYLOAD(rta), sizeof(cacheinfo), msgtype);
                continue;
            }

            cacheinfo = (struct ifa_cacheinfo *) RTA_DATA(rta);
        }
    }

    if (addrstr[0] == '\0') {
        SLOGE("No IFA_ADDRESS in %s\n", msgtype);
        return false;
    }

    // Fill in netlink event information.
    mAction = (type == RTM_NEWADDR) ? Action::kAddressUpdated :
                                      Action::kAddressRemoved;
    mSubsystem = strdup("net");
    asprintf(&mParams[0], "ADDRESS=%s/%d", addrstr,
             ifaddr->ifa_prefixlen);
    asprintf(&mParams[1], "INTERFACE=%s", ifname);
    asprintf(&mParams[2], "FLAGS=%u", ifaddr->ifa_flags);
    asprintf(&mParams[3], "SCOPE=%u", ifaddr->ifa_scope);

    if (cacheinfo) {
        asprintf(&mParams[4], "PREFERRED=%u", cacheinfo->ifa_prefered);
        asprintf(&mParams[5], "VALID=%u", cacheinfo->ifa_valid);
        asprintf(&mParams[6], "CSTAMP=%u", cacheinfo->cstamp);
        asprintf(&mParams[7], "TSTAMP=%u", cacheinfo->tstamp);
    }

    return true;
}

/*
 * Parse a QLOG_NL_EVENT message.
 */
bool NetlinkEvent::parseUlogPacketMessage(const struct nlmsghdr *nh) {
    const char *devname;
    ulog_packet_msg_t *pm = (ulog_packet_msg_t *) NLMSG_DATA(nh);
    if (!checkRtNetlinkLength(nh, sizeof(*pm)))
        return false;

    devname = pm->indev_name[0] ? pm->indev_name : pm->outdev_name;
    asprintf(&mParams[0], "ALERT_NAME=%s", pm->prefix);
    asprintf(&mParams[1], "INTERFACE=%s", devname);
    mSubsystem = strdup("qlog");
    mAction = Action::kChange;
    return true;
}

/*
 * Parse a LOCAL_NFLOG_PACKET message.
 */
bool NetlinkEvent::parseNfPacketMessage(struct nlmsghdr *nh) {
    int uid = -1;
    int len = 0;
    char* raw = NULL;

    struct nlattr *uid_attr = nlmsg_find_attr(nh, sizeof(struct genlmsghdr), NFULA_UID);
    if (uid_attr) {
        uid = ntohl(nla_get_u32(uid_attr));
    }

    struct nlattr *payload = nlmsg_find_attr(nh, sizeof(struct genlmsghdr), NFULA_PAYLOAD);
    if (payload) {
        /* First 256 bytes is plenty */
        len = nla_len(payload);
        if (len > 256) len = 256;
        raw = (char*) nla_data(payload);
    }

    char* hex = (char*) calloc(1, 5 + (len * 2));
    strcpy(hex, "HEX=");
    for (int i = 0; i < len; i++) {
        hex[4 + (i * 2)] = "0123456789abcdef"[(raw[i] >> 4) & 0xf];
        hex[5 + (i * 2)] = "0123456789abcdef"[raw[i] & 0xf];
    }

    asprintf(&mParams[0], "UID=%d", uid);
    mParams[1] = hex;
    mSubsystem = strdup("strict");
    mAction = Action::kChange;
    return true;
}

/*
 * Parse a RTM_NEWROUTE or RTM_DELROUTE message.
 */
bool NetlinkEvent::parseRtMessage(const struct nlmsghdr *nh) {
    uint8_t type = nh->nlmsg_type;
    const char *msgname = rtMessageName(type);

    // Sanity check.
    if (type != RTM_NEWROUTE && type != RTM_DELROUTE) {
        SLOGE("%s: incorrect message type %d (%s)\n", __func__, type, msgname);
        return false;
    }

    struct rtmsg *rtm = (struct rtmsg *) NLMSG_DATA(nh);
    if (!checkRtNetlinkLength(nh, sizeof(*rtm)))
        return false;

    if (// Ignore static routes we've set up ourselves.
        (rtm->rtm_protocol != RTPROT_KERNEL &&
         rtm->rtm_protocol != RTPROT_RA) ||
        // We're only interested in global unicast routes.
        (rtm->rtm_scope != RT_SCOPE_UNIVERSE) ||
        (rtm->rtm_type != RTN_UNICAST) ||
        // We don't support source routing.
        (rtm->rtm_src_len != 0) ||
        // Cloned routes aren't real routes.
        (rtm->rtm_flags & RTM_F_CLONED)) {
        return false;
    }

    int family = rtm->rtm_family;
    int prefixLength = rtm->rtm_dst_len;

    // Currently we only support: destination, (one) next hop, ifindex.
    char dst[INET6_ADDRSTRLEN] = "";
    char gw[INET6_ADDRSTRLEN] = "";
    char dev[IFNAMSIZ] = "";

    size_t len = RTM_PAYLOAD(nh);
    struct rtattr *rta;
    for (rta = RTM_RTA(rtm); RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
        switch (rta->rta_type) {
            case RTA_DST:
                if (maybeLogDuplicateAttribute(*dst, "RTA_DST", msgname))
                    continue;
                if (!inet_ntop(family, RTA_DATA(rta), dst, sizeof(dst)))
                    return false;
                continue;
            case RTA_GATEWAY:
                if (maybeLogDuplicateAttribute(*gw, "RTA_GATEWAY", msgname))
                    continue;
                if (!inet_ntop(family, RTA_DATA(rta), gw, sizeof(gw)))
                    return false;
                continue;
            case RTA_OIF:
                if (maybeLogDuplicateAttribute(*dev, "RTA_OIF", msgname))
                    continue;
                if (!if_indextoname(* (int *) RTA_DATA(rta), dev))
                    return false;
            default:
                continue;
        }
    }

   // If there's no RTA_DST attribute, then:
   // - If the prefix length is zero, it's the default route.
   // - If the prefix length is nonzero, there's something we don't understand.
   //   Ignore the event.
   if (!*dst && !prefixLength) {
        if (family == AF_INET) {
            strncpy(dst, "0.0.0.0", sizeof(dst));
        } else if (family == AF_INET6) {
            strncpy(dst, "::", sizeof(dst));
        }
    }

    // A useful route must have a destination and at least either a gateway or
    // an interface.
    if (!*dst || (!*gw && !*dev))
        return false;

    // Fill in netlink event information.
    mAction = (type == RTM_NEWROUTE) ? Action::kRouteUpdated :
                                       Action::kRouteRemoved;
    mSubsystem = strdup("net");
    asprintf(&mParams[0], "ROUTE=%s/%d", dst, prefixLength);
    asprintf(&mParams[1], "GATEWAY=%s", (*gw) ? gw : "");
    asprintf(&mParams[2], "INTERFACE=%s", (*dev) ? dev : "");

    return true;
}

/*
 * Parse a RTM_NEWNDUSEROPT message.
 */
bool NetlinkEvent::parseNdUserOptMessage(const struct nlmsghdr *nh) {
    struct nduseroptmsg *msg = (struct nduseroptmsg *) NLMSG_DATA(nh);
    if (!checkRtNetlinkLength(nh, sizeof(*msg)))
        return false;

    // Check the length is valid.
    int len = NLMSG_PAYLOAD(nh, sizeof(*msg));
    if (msg->nduseropt_opts_len > len) {
        SLOGE("RTM_NEWNDUSEROPT invalid length %d > %d\n",
              msg->nduseropt_opts_len, len);
        return false;
    }
    len = msg->nduseropt_opts_len;

    // Check address family and packet type.
    if (msg->nduseropt_family != AF_INET6) {
        SLOGE("RTM_NEWNDUSEROPT message for unknown family %d\n",
              msg->nduseropt_family);
        return false;
    }

    if (msg->nduseropt_icmp_type != ND_ROUTER_ADVERT ||
        msg->nduseropt_icmp_code != 0) {
        SLOGE("RTM_NEWNDUSEROPT message for unknown ICMPv6 type/code %d/%d\n",
              msg->nduseropt_icmp_type, msg->nduseropt_icmp_code);
        return false;
    }

    // Find the interface name.
    char ifname[IFNAMSIZ];
    if (!if_indextoname(msg->nduseropt_ifindex, ifname)) {
        SLOGE("RTM_NEWNDUSEROPT on unknown ifindex %d\n",
              msg->nduseropt_ifindex);
        return false;
    }

    // The kernel sends a separate netlink message for each ND option in the RA.
    // So only parse the first ND option in the message.
    struct nd_opt_hdr *opthdr = (struct nd_opt_hdr *) (msg + 1);

    // The length is in multiples of 8 octets.
    uint16_t optlen = opthdr->nd_opt_len;
    if (optlen * 8 > len) {
        SLOGE("Invalid option length %d > %d for ND option %d\n",
              optlen * 8, len, opthdr->nd_opt_type);
        return false;
    }

    if (opthdr->nd_opt_type == ND_OPT_RDNSS) {
        // DNS Servers (RFC 6106).
        // Each address takes up 2*8 octets, and the header takes up 8 octets.
        // So for a valid option with one or more addresses, optlen must be
        // odd and greater than 1.
        if ((optlen < 3) || !(optlen & 0x1)) {
            SLOGE("Invalid optlen %d for RDNSS option\n", optlen);
            return false;
        }
        const int numaddrs = (optlen - 1) / 2;

        // Find the lifetime.
        struct nd_opt_rdnss *rndss_opt = (struct nd_opt_rdnss *) opthdr;
        const uint32_t lifetime = ntohl(rndss_opt->nd_opt_rdnss_lifetime);

        // Construct "SERVERS=<comma-separated string of DNS addresses>".
        static const char kServerTag[] = "SERVERS=";
        static const size_t kTagLength = strlen(kServerTag);
        // Reserve sufficient space for an IPv6 link-local address: all but the
        // last address are followed by ','; the last is followed by '\0'.
        static const size_t kMaxSingleAddressLength =
                INET6_ADDRSTRLEN + strlen("%") + IFNAMSIZ + strlen(",");
        const size_t bufsize = kTagLength + numaddrs * kMaxSingleAddressLength;
        char *buf = (char *) malloc(bufsize);
        if (!buf) {
            SLOGE("RDNSS option: out of memory\n");
            return false;
        }
        strcpy(buf, kServerTag);
        size_t pos = kTagLength;

        struct in6_addr *addrs = (struct in6_addr *) (rndss_opt + 1);
        for (int i = 0; i < numaddrs; i++) {
            if (i > 0) {
                buf[pos++] = ',';
            }
            inet_ntop(AF_INET6, addrs + i, buf + pos, bufsize - pos);
            pos += strlen(buf + pos);
            if (IN6_IS_ADDR_LINKLOCAL(addrs + i)) {
                buf[pos++] = '%';
                pos += strlcpy(buf + pos, ifname, bufsize - pos);
            }
        }
        buf[pos] = '\0';

        mAction = Action::kRdnss;
        mSubsystem = strdup("net");
        asprintf(&mParams[0], "INTERFACE=%s", ifname);
        asprintf(&mParams[1], "LIFETIME=%u", lifetime);
        mParams[2] = buf;
    } else {
        SLOGD("Unknown ND option type %d\n", opthdr->nd_opt_type);
        return false;
    }

    return true;
}

/*
 * Parse a binary message from a NETLINK_ROUTE netlink socket.
 *
 * Note that this function can only parse one message, because the message's
 * content has to be stored in the class's member variables (mAction,
 * mSubsystem, etc.). Invalid or unrecognized messages are skipped, but if
 * there are multiple valid messages in the buffer, only the first one will be
 * returned.
 *
 * TODO: consider only ever looking at the first message.
 */
bool NetlinkEvent::parseBinaryNetlinkMessage(char *buffer, int size) {
    struct nlmsghdr *nh;

    for (nh = (struct nlmsghdr *) buffer;
         NLMSG_OK(nh, (unsigned) size) && (nh->nlmsg_type != NLMSG_DONE);
         nh = NLMSG_NEXT(nh, size)) {

        if (!rtMessageName(nh->nlmsg_type)) {
            SLOGD("Unexpected netlink message type %d\n", nh->nlmsg_type);
            continue;
        }

        if (nh->nlmsg_type == RTM_NEWLINK) {
            if (parseIfInfoMessage(nh))
                return true;

        } else if (nh->nlmsg_type == LOCAL_QLOG_NL_EVENT) {
            if (parseUlogPacketMessage(nh))
                return true;

        } else if (nh->nlmsg_type == RTM_NEWADDR ||
                   nh->nlmsg_type == RTM_DELADDR) {
            if (parseIfAddrMessage(nh))
                return true;

        } else if (nh->nlmsg_type == RTM_NEWROUTE ||
                   nh->nlmsg_type == RTM_DELROUTE) {
            if (parseRtMessage(nh))
                return true;

        } else if (nh->nlmsg_type == RTM_NEWNDUSEROPT) {
            if (parseNdUserOptMessage(nh))
                return true;

        } else if (nh->nlmsg_type == LOCAL_NFLOG_PACKET) {
            if (parseNfPacketMessage(nh))
                return true;

        }
    }

    return false;
}

/* If the string between 'str' and 'end' begins with 'prefixlen' characters
 * from the 'prefix' array, then return 'str + prefixlen', otherwise return
 * NULL.
 */
static const char*
has_prefix(const char* str, const char* end, const char* prefix, size_t prefixlen)
{
    if ((end-str) >= (ptrdiff_t)prefixlen && !memcmp(str, prefix, prefixlen))
        return str + prefixlen;
    else
        return NULL;
}

/* Same as strlen(x) for constant string literals ONLY */
#define CONST_STRLEN(x)  (sizeof(x)-1)

/* Convenience macro to call has_prefix with a constant string literal  */
#define HAS_CONST_PREFIX(str,end,prefix)  has_prefix((str),(end),prefix,CONST_STRLEN(prefix))


/*
 * Parse an ASCII-formatted message from a NETLINK_KOBJECT_UEVENT
 * netlink socket.
 */
bool NetlinkEvent::parseAsciiNetlinkMessage(char *buffer, int size) {
    const char *s = buffer;
    const char *end;
    int param_idx = 0;
    int first = 1;

    if (size == 0)
        return false;

    /* Ensure the buffer is zero-terminated, the code below depends on this */
    buffer[size-1] = '\0';

    end = s + size;
    while (s < end) {
        if (first) {
            const char *p;
            /* buffer is 0-terminated, no need to check p < end */
            for (p = s; *p != '@'; p++) {
                if (!*p) { /* no '@', should not happen */
                    return false;
                }
            }
            mPath = strdup(p+1);
            first = 0;
        } else {
            const char* a;
            if ((a = HAS_CONST_PREFIX(s, end, "ACTION=")) != NULL) {
                if (!strcmp(a, "add"))
                    mAction = Action::kAdd;
                else if (!strcmp(a, "remove"))
                    mAction = Action::kRemove;
                else if (!strcmp(a, "change"))
                    mAction = Action::kChange;
            } else if ((a = HAS_CONST_PREFIX(s, end, "SEQNUM=")) != NULL) {
                mSeq = atoi(a);
            } else if ((a = HAS_CONST_PREFIX(s, end, "SUBSYSTEM=")) != NULL) {
                mSubsystem = strdup(a);
            } else if (param_idx < NL_PARAMS_MAX) {
                mParams[param_idx++] = strdup(s);
            }
        }
        s += strlen(s) + 1;
    }
    return true;
}

bool NetlinkEvent::decode(char *buffer, int size, int format) {
    if (format == NetlinkListener::NETLINK_FORMAT_BINARY
            || format == NetlinkListener::NETLINK_FORMAT_BINARY_UNICAST) {
        return parseBinaryNetlinkMessage(buffer, size);
    } else {
        return parseAsciiNetlinkMessage(buffer, size);
    }
}

const char *NetlinkEvent::findParam(const char *paramName) {
    size_t len = strlen(paramName);
    for (int i = 0; i < NL_PARAMS_MAX && mParams[i] != NULL; ++i) {
        const char *ptr = mParams[i] + len;
        if (!strncmp(mParams[i], paramName, len) && *ptr == '=')
            return ++ptr;
    }

    SLOGE("NetlinkEvent::FindParam(): Parameter '%s' not found", paramName);
    return NULL;
}

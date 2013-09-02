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
#include <arpa/inet.h>
#include <net/if.h>

#include <linux/if.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter_ipv4/ipt_ULOG.h>
/* From kernel's net/netfilter/xt_quota2.c */
const int QLOG_NL_EVENT  = 112;

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

const int NetlinkEvent::NlActionUnknown = 0;
const int NetlinkEvent::NlActionAdd = 1;
const int NetlinkEvent::NlActionRemove = 2;
const int NetlinkEvent::NlActionChange = 3;
const int NetlinkEvent::NlActionLinkUp = 4;
const int NetlinkEvent::NlActionLinkDown = 5;
const int NetlinkEvent::NlActionAddressUpdated = 6;
const int NetlinkEvent::NlActionAddressRemoved = 7;

NetlinkEvent::NetlinkEvent() {
    mAction = NlActionUnknown;
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
 * Decode a RTM_NEWADDR or RTM_DELADDR message.
 */
bool NetlinkEvent::parseIfAddrMessage(int type, struct ifaddrmsg *ifaddr,
                                      int rtasize) {
    struct rtattr *rta;
    struct ifa_cacheinfo *cacheinfo = NULL;
    char addrstr[INET6_ADDRSTRLEN] = "";

    // Sanity check.
    if (type != RTM_NEWADDR && type != RTM_DELADDR) {
        SLOGE("parseIfAddrMessage on incorrect message type 0x%x\n", type);
        return false;
    }

    // For log messages.
    const char *msgtype = (type == RTM_NEWADDR) ? "RTM_NEWADDR" : "RTM_DELADDR";

    for (rta = IFA_RTA(ifaddr); RTA_OK(rta, rtasize);
         rta = RTA_NEXT(rta, rtasize)) {
        if (rta->rta_type == IFA_ADDRESS) {
            // Only look at the first address, because we only support notifying
            // one change at a time.
            if (*addrstr != '\0') {
                SLOGE("Multiple IFA_ADDRESSes in %s, ignoring\n", msgtype);
                continue;
            }

            // Convert the IP address to a string.
            if (ifaddr->ifa_family == AF_INET) {
                struct in_addr *addr4 = (struct in_addr *) RTA_DATA(rta);
                if (RTA_PAYLOAD(rta) < sizeof(*addr4)) {
                    SLOGE("Short IPv4 address (%d bytes) in %s",
                          RTA_PAYLOAD(rta), msgtype);
                    continue;
                }
                inet_ntop(AF_INET, addr4, addrstr, sizeof(addrstr));
            } else if (ifaddr->ifa_family == AF_INET6) {
                struct in6_addr *addr6 = (struct in6_addr *) RTA_DATA(rta);
                if (RTA_PAYLOAD(rta) < sizeof(*addr6)) {
                    SLOGE("Short IPv6 address (%d bytes) in %s",
                          RTA_PAYLOAD(rta), msgtype);
                    continue;
                }
                inet_ntop(AF_INET6, addr6, addrstr, sizeof(addrstr));
            } else {
                SLOGE("Unknown address family %d\n", ifaddr->ifa_family);
                continue;
            }

            // Find the interface name.
            char ifname[IFNAMSIZ + 1];
            if (!if_indextoname(ifaddr->ifa_index, ifname)) {
                SLOGE("Unknown ifindex %d in %s", ifaddr->ifa_index, msgtype);
                return false;
            }

            // Fill in interface information.
            mAction = (type == RTM_NEWADDR) ? NlActionAddressUpdated :
                                              NlActionAddressRemoved;
            mSubsystem = strdup("net");
            asprintf(&mParams[0], "ADDRESS=%s/%d", addrstr,
                     ifaddr->ifa_prefixlen);
            asprintf(&mParams[1], "INTERFACE=%s", ifname);
            asprintf(&mParams[2], "FLAGS=%u", ifaddr->ifa_flags);
            asprintf(&mParams[3], "SCOPE=%u", ifaddr->ifa_scope);
        } else if (rta->rta_type == IFA_CACHEINFO) {
            // Address lifetime information.
            if (cacheinfo) {
                // We only support one address.
                SLOGE("Multiple IFA_CACHEINFOs in %s, ignoring\n", msgtype);
                continue;
            }

            if (RTA_PAYLOAD(rta) < sizeof(*cacheinfo)) {
                SLOGE("Short IFA_CACHEINFO (%d vs. %d bytes) in %s",
                      RTA_PAYLOAD(rta), sizeof(cacheinfo), msgtype);
                continue;
            }

            cacheinfo = (struct ifa_cacheinfo *) RTA_DATA(rta);
            asprintf(&mParams[4], "PREFERRED=%u", cacheinfo->ifa_prefered);
            asprintf(&mParams[5], "VALID=%u", cacheinfo->ifa_valid);
            asprintf(&mParams[6], "CSTAMP=%u", cacheinfo->cstamp);
            asprintf(&mParams[7], "TSTAMP=%u", cacheinfo->tstamp);
        }
    }

    if (addrstr[0] == '\0') {
        SLOGE("No IFA_ADDRESS in %s\n", msgtype);
        return false;
    }

    return true;
}

/*
 * Parse an binary message from a NETLINK_ROUTE netlink socket.
 */
bool NetlinkEvent::parseBinaryNetlinkMessage(char *buffer, int size) {
    const struct nlmsghdr *nh;

    for (nh = (struct nlmsghdr *) buffer;
         NLMSG_OK(nh, size) && (nh->nlmsg_type != NLMSG_DONE);
         nh = NLMSG_NEXT(nh, size)) {

        if (nh->nlmsg_type == RTM_NEWLINK) {
            int len = nh->nlmsg_len - sizeof(*nh);
            struct ifinfomsg *ifi;

            if (sizeof(*ifi) > (size_t) len) {
                SLOGE("Got a short RTM_NEWLINK message\n");
                continue;
            }

            ifi = (ifinfomsg *)NLMSG_DATA(nh);
            if ((ifi->ifi_flags & IFF_LOOPBACK) != 0) {
                continue;
            }

            struct rtattr *rta = (struct rtattr *)
              ((char *) ifi + NLMSG_ALIGN(sizeof(*ifi)));
            len = NLMSG_PAYLOAD(nh, sizeof(*ifi));

            while(RTA_OK(rta, len)) {
                switch(rta->rta_type) {
                case IFLA_IFNAME:
                    char buffer[16 + IFNAMSIZ];
                    snprintf(buffer, sizeof(buffer), "INTERFACE=%s",
                             (char *) RTA_DATA(rta));
                    mParams[0] = strdup(buffer);
                    mAction = (ifi->ifi_flags & IFF_LOWER_UP) ?
                      NlActionLinkUp : NlActionLinkDown;
                    mSubsystem = strdup("net");
                    break;
                }

                rta = RTA_NEXT(rta, len);
            }

        } else if (nh->nlmsg_type == QLOG_NL_EVENT) {
            char *devname;
            ulog_packet_msg_t *pm;
            size_t len = nh->nlmsg_len - sizeof(*nh);
            if (sizeof(*pm) > len) {
                SLOGE("Got a short QLOG message\n");
                continue;
            }
            pm = (ulog_packet_msg_t *)NLMSG_DATA(nh);
            devname = pm->indev_name[0] ? pm->indev_name : pm->outdev_name;
            asprintf(&mParams[0], "ALERT_NAME=%s", pm->prefix);
            asprintf(&mParams[1], "INTERFACE=%s", devname);
            mSubsystem = strdup("qlog");
            mAction = NlActionChange;

        } else if (nh->nlmsg_type == RTM_NEWADDR ||
                   nh->nlmsg_type == RTM_DELADDR) {
            int len = nh->nlmsg_len - sizeof(*nh);
            struct ifaddrmsg *ifa;

            if (sizeof(*ifa) > (size_t) len) {
                SLOGE("Got a short RTM_xxxADDR message\n");
                continue;
            }

            ifa = (ifaddrmsg *)NLMSG_DATA(nh);
            size_t rtasize = IFA_PAYLOAD(nh);
            if (!parseIfAddrMessage(nh->nlmsg_type, ifa, rtasize)) {
                continue;
            }
        } else {
                SLOGD("Unexpected netlink message. type=0x%x\n", nh->nlmsg_type);
        }
    }

    return true;
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
    int i;
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
                    mAction = NlActionAdd;
                else if (!strcmp(a, "remove"))
                    mAction = NlActionRemove;
                else if (!strcmp(a, "change"))
                    mAction = NlActionChange;
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
    if (format == NetlinkListener::NETLINK_FORMAT_BINARY) {
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

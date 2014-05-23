/*
 * Copyright 2008, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <time.h>
#include <sys/time.h>
#include <poll.h>

#include <sys/socket.h>
#include <sys/select.h>
#include <sys/types.h>
#include <netinet/in.h>

#include <cutils/properties.h>
#define LOG_TAG "DHCP"
#include <cutils/log.h>

#include <dirent.h>

#include <netutils/ifc.h>
#include "dhcpmsg.h"
#include "packet.h"

#define VERBOSE 2

static int verbose = 1;
static char errmsg[2048];

typedef unsigned long long msecs_t;
#if VERBOSE
void dump_dhcp_msg();
#endif

msecs_t get_msecs(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts)) {
        return 0;
    } else {
        return (((msecs_t) ts.tv_sec) * ((msecs_t) 1000)) +
            (((msecs_t) ts.tv_nsec) / ((msecs_t) 1000000));
    }
}

void printerr(char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(errmsg, sizeof(errmsg), fmt, ap);
    va_end(ap);

    ALOGD("%s", errmsg);
}

const char *dhcp_lasterror()
{
    return errmsg;
}

int fatal(const char *reason)
{
    printerr("%s: %s\n", reason, strerror(errno));
    return -1;
//    exit(1);
}

const char *ipaddr(in_addr_t addr)
{
    struct in_addr in_addr;

    in_addr.s_addr = addr;
    return inet_ntoa(in_addr);
}

extern int ipv4NetmaskToPrefixLength(in_addr_t mask);

typedef struct dhcp_info dhcp_info;

struct dhcp_info {
    uint32_t type;

    uint32_t ipaddr;
    uint32_t gateway;
    uint32_t prefixLength;

    uint32_t dns1;
    uint32_t dns2;

    uint32_t serveraddr;
    uint32_t lease;
};

dhcp_info last_good_info;

void get_dhcp_info(uint32_t *ipaddr, uint32_t *gateway, uint32_t *prefixLength,
                   uint32_t *dns1, uint32_t *dns2, uint32_t *server,
                   uint32_t *lease)
{
    *ipaddr = last_good_info.ipaddr;
    *gateway = last_good_info.gateway;
    *prefixLength = last_good_info.prefixLength;
    *dns1 = last_good_info.dns1;
    *dns2 = last_good_info.dns2;
    *server = last_good_info.serveraddr;
    *lease = last_good_info.lease;
}

static int dhcp_configure(const char *ifname, dhcp_info *info)
{
    last_good_info = *info;
    return ifc_configure(ifname, info->ipaddr, info->prefixLength, info->gateway,
                         info->dns1, info->dns2);
}

static const char *dhcp_type_to_name(uint32_t type)
{
    switch(type) {
    case DHCPDISCOVER: return "discover";
    case DHCPOFFER:    return "offer";
    case DHCPREQUEST:  return "request";
    case DHCPDECLINE:  return "decline";
    case DHCPACK:      return "ack";
    case DHCPNAK:      return "nak";
    case DHCPRELEASE:  return "release";
    case DHCPINFORM:   return "inform";
    default:           return "???";
    }
}

void dump_dhcp_info(dhcp_info *info)
{
    char addr[20], gway[20], mask[20];
    ALOGD("--- dhcp %s (%d) ---",
            dhcp_type_to_name(info->type), info->type);
    strcpy(addr, ipaddr(info->ipaddr));
    strcpy(gway, ipaddr(info->gateway));
    ALOGD("ip %s gw %s prefixLength %d", addr, gway, info->prefixLength);
    if (info->dns1) ALOGD("dns1: %s", ipaddr(info->dns1));
    if (info->dns2) ALOGD("dns2: %s", ipaddr(info->dns2));
    ALOGD("server %s, lease %d seconds",
            ipaddr(info->serveraddr), info->lease);
}


int decode_dhcp_msg(dhcp_msg *msg, int len, dhcp_info *info)
{
    uint8_t *x;
    unsigned int opt;
    int optlen;

    memset(info, 0, sizeof(dhcp_info));
    if (len < (DHCP_MSG_FIXED_SIZE + 4)) return -1;

    len -= (DHCP_MSG_FIXED_SIZE + 4);

    if (msg->options[0] != OPT_COOKIE1) return -1;
    if (msg->options[1] != OPT_COOKIE2) return -1;
    if (msg->options[2] != OPT_COOKIE3) return -1;
    if (msg->options[3] != OPT_COOKIE4) return -1;

    x = msg->options + 4;

    while (len > 2) {
        opt = *x++;
        if (opt == OPT_PAD) {
            len--;
            continue;
        }
        if (opt == OPT_END) {
            break;
        }
        optlen = *x++;
        len -= 2;
        if (optlen > len) {
            break;
        }
        switch(opt) {
        case OPT_SUBNET_MASK:
            if (optlen >= 4) {
                in_addr_t mask;
                memcpy(&mask, x, 4);
                info->prefixLength = ipv4NetmaskToPrefixLength(mask);
            }
            break;
        case OPT_GATEWAY:
            if (optlen >= 4) memcpy(&info->gateway, x, 4);
            break;
        case OPT_DNS:
            if (optlen >= 4) memcpy(&info->dns1, x + 0, 4);
            if (optlen >= 8) memcpy(&info->dns2, x + 4, 4);
            break;
        case OPT_LEASE_TIME:
            if (optlen >= 4) {
                memcpy(&info->lease, x, 4);
                info->lease = ntohl(info->lease);
            }
            break;
        case OPT_SERVER_ID:
            if (optlen >= 4) memcpy(&info->serveraddr, x, 4);
            break;
        case OPT_MESSAGE_TYPE:
            info->type = *x;
            break;
        default:
            break;
        }
        x += optlen;
        len -= optlen;
    }

    info->ipaddr = msg->yiaddr;

    return 0;
}

#if VERBOSE

static void hex2str(char *buf, const unsigned char *array, int len)
{
    int i;
    char *cp = buf;

    for (i = 0; i < len; i++) {
        cp += sprintf(cp, " %02x ", array[i]);
    }
}

void dump_dhcp_msg(dhcp_msg *msg, int len)
{
    unsigned char *x;
    unsigned int n,c;
    int optsz;
    const char *name;
    char buf[2048];

    ALOGD("===== DHCP message:");
    if (len < DHCP_MSG_FIXED_SIZE) {
        ALOGD("Invalid length %d, should be %d", len, DHCP_MSG_FIXED_SIZE);
        return;
    }

    len -= DHCP_MSG_FIXED_SIZE;

    if (msg->op == OP_BOOTREQUEST)
        name = "BOOTREQUEST";
    else if (msg->op == OP_BOOTREPLY)
        name = "BOOTREPLY";
    else
        name = "????";
    ALOGD("op = %s (%d), htype = %d, hlen = %d, hops = %d",
           name, msg->op, msg->htype, msg->hlen, msg->hops);
    ALOGD("xid = 0x%08x secs = %d, flags = 0x%04x optlen = %d",
           ntohl(msg->xid), ntohs(msg->secs), ntohs(msg->flags), len);
    ALOGD("ciaddr = %s", ipaddr(msg->ciaddr));
    ALOGD("yiaddr = %s", ipaddr(msg->yiaddr));
    ALOGD("siaddr = %s", ipaddr(msg->siaddr));
    ALOGD("giaddr = %s", ipaddr(msg->giaddr));

    c = msg->hlen > 16 ? 16 : msg->hlen;
    hex2str(buf, msg->chaddr, c);
    ALOGD("chaddr = {%s}", buf);

    for (n = 0; n < 64; n++) {
        unsigned char x = msg->sname[n];
        if ((x < ' ') || (x > 127)) {
            if (x == 0) break;
            msg->sname[n] = '.';
        }
    }
    msg->sname[63] = 0;

    for (n = 0; n < 128; n++) {
        unsigned char x = msg->file[n];
        if ((x < ' ') || (x > 127)) {
            if (x == 0) break;
            msg->file[n] = '.';
        }
    }
    msg->file[127] = 0;

    ALOGD("sname = '%s'", msg->sname);
    ALOGD("file = '%s'", msg->file);

    if (len < 4) return;
    len -= 4;
    x = msg->options + 4;

    while (len > 2) {
        if (*x == 0) {
            x++;
            len--;
            continue;
        }
        if (*x == OPT_END) {
            break;
        }
        len -= 2;
        optsz = x[1];
        if (optsz > len) break;
        if (x[0] == OPT_DOMAIN_NAME || x[0] == OPT_MESSAGE) {
            if ((unsigned int)optsz < sizeof(buf) - 1) {
                n = optsz;
            } else {
                n = sizeof(buf) - 1;
            }
            memcpy(buf, &x[2], n);
            buf[n] = '\0';
        } else {
            hex2str(buf, &x[2], optsz);
        }
        if (x[0] == OPT_MESSAGE_TYPE)
            name = dhcp_type_to_name(x[2]);
        else
            name = NULL;
        ALOGD("op %d len %d {%s} %s", x[0], optsz, buf, name == NULL ? "" : name);
        len -= optsz;
        x = x + optsz + 2;
    }
}

#endif

static int send_message(int sock, int if_index, dhcp_msg  *msg, int size)
{
#if VERBOSE > 1
    dump_dhcp_msg(msg, size);
#endif
    return send_packet(sock, if_index, msg, size, INADDR_ANY, INADDR_BROADCAST,
                       PORT_BOOTP_CLIENT, PORT_BOOTP_SERVER);
}

static int is_valid_reply(dhcp_msg *msg, dhcp_msg *reply, int sz)
{
    if (sz < DHCP_MSG_FIXED_SIZE) {
        if (verbose) ALOGD("netcfg: Wrong size %d != %d\n", sz, DHCP_MSG_FIXED_SIZE);
        return 0;
    }
    if (reply->op != OP_BOOTREPLY) {
        if (verbose) ALOGD("netcfg: Wrong Op %d != %d\n", reply->op, OP_BOOTREPLY);
        return 0;
    }
    if (reply->xid != msg->xid) {
        if (verbose) ALOGD("netcfg: Wrong Xid 0x%x != 0x%x\n", ntohl(reply->xid),
                          ntohl(msg->xid));
        return 0;
    }
    if (reply->htype != msg->htype) {
        if (verbose) ALOGD("netcfg: Wrong Htype %d != %d\n", reply->htype, msg->htype);
        return 0;
    }
    if (reply->hlen != msg->hlen) {
        if (verbose) ALOGD("netcfg: Wrong Hlen %d != %d\n", reply->hlen, msg->hlen);
        return 0;
    }
    if (memcmp(msg->chaddr, reply->chaddr, msg->hlen)) {
        if (verbose) ALOGD("netcfg: Wrong chaddr %x != %x\n", *(reply->chaddr),*(msg->chaddr));
        return 0;
    }
    return 1;
}

#define STATE_SELECTING  1
#define STATE_REQUESTING 2

#define TIMEOUT_INITIAL   4000
#define TIMEOUT_MAX      32000

int dhcp_init_ifc(const char *ifname)
{
    dhcp_msg discover_msg;
    dhcp_msg request_msg;
    dhcp_msg reply;
    dhcp_msg *msg;
    dhcp_info info;
    int s, r, size;
    int valid_reply;
    uint32_t xid;
    unsigned char hwaddr[6];
    struct pollfd pfd;
    unsigned int state;
    unsigned int timeout;
    int if_index;

    xid = (uint32_t) get_msecs();

    if (ifc_get_hwaddr(ifname, hwaddr)) {
        return fatal("cannot obtain interface address");
    }
    if (ifc_get_ifindex(ifname, &if_index)) {
        return fatal("cannot obtain interface index");
    }

    s = open_raw_socket(ifname, hwaddr, if_index);

    timeout = TIMEOUT_INITIAL;
    state = STATE_SELECTING;
    info.type = 0;
    goto transmit;

    for (;;) {
        pfd.fd = s;
        pfd.events = POLLIN;
        pfd.revents = 0;
        r = poll(&pfd, 1, timeout);

        if (r == 0) {
#if VERBOSE
            printerr("TIMEOUT\n");
#endif
            if (timeout >= TIMEOUT_MAX) {
                printerr("timed out\n");
                if ( info.type == DHCPOFFER ) {
                    printerr("no acknowledgement from DHCP server\nconfiguring %s with offered parameters\n", ifname);
                    return dhcp_configure(ifname, &info);
                }
                errno = ETIME;
                close(s);
                return -1;
            }
            timeout = timeout * 2;

        transmit:
            size = 0;
            msg = NULL;
            switch(state) {
            case STATE_SELECTING:
                msg = &discover_msg;
                size = init_dhcp_discover_msg(msg, hwaddr, xid);
                break;
            case STATE_REQUESTING:
                msg = &request_msg;
                size = init_dhcp_request_msg(msg, hwaddr, xid, info.ipaddr, info.serveraddr);
                break;
            default:
                r = 0;
            }
            if (size != 0) {
                r = send_message(s, if_index, msg, size);
                if (r < 0) {
                    printerr("error sending dhcp msg: %s\n", strerror(errno));
                }
            }
            continue;
        }

        if (r < 0) {
            if ((errno == EAGAIN) || (errno == EINTR)) {
                continue;
            }
            return fatal("poll failed");
        }

        errno = 0;
        r = receive_packet(s, &reply);
        if (r < 0) {
            if (errno != 0) {
                ALOGD("receive_packet failed (%d): %s", r, strerror(errno));
                if (errno == ENETDOWN || errno == ENXIO) {
                    return -1;
                }
            }
            continue;
        }

#if VERBOSE > 1
        dump_dhcp_msg(&reply, r);
#endif
        decode_dhcp_msg(&reply, r, &info);

        if (state == STATE_SELECTING) {
            valid_reply = is_valid_reply(&discover_msg, &reply, r);
        } else {
            valid_reply = is_valid_reply(&request_msg, &reply, r);
        }
        if (!valid_reply) {
            printerr("invalid reply\n");
            continue;
        }

        if (verbose) dump_dhcp_info(&info);

        switch(state) {
        case STATE_SELECTING:
            if (info.type == DHCPOFFER) {
                state = STATE_REQUESTING;
                timeout = TIMEOUT_INITIAL;
                xid++;
                goto transmit;
            }
            break;
        case STATE_REQUESTING:
            if (info.type == DHCPACK) {
                printerr("configuring %s\n", ifname);
                close(s);
                return dhcp_configure(ifname, &info);
            } else if (info.type == DHCPNAK) {
                printerr("configuration request denied\n");
                close(s);
                return -1;
            } else {
                printerr("ignoring %s message in state %d\n",
                         dhcp_type_to_name(info.type), state);
            }
            break;
        }
    }
    close(s);
    return 0;
}

int do_dhcp(char *iname)
{
    if (ifc_set_addr(iname, 0)) {
        printerr("failed to set ip addr for %s to 0.0.0.0: %s\n", iname, strerror(errno));
        return -1;
    }

    if (ifc_up(iname)) {
        printerr("failed to bring up interface %s: %s\n", iname, strerror(errno));
        return -1;
    }

    return dhcp_init_ifc(iname);
}

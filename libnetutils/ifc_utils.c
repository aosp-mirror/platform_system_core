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
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <sys/socket.h>
#include <sys/select.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netdb.h>

#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/netlink.h>
#include <linux/route.h>
#include <linux/ipv6_route.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>

#include "netutils/ifc.h"

#ifdef ANDROID
#define LOG_TAG "NetUtils"
#include <cutils/log.h>
#include <cutils/properties.h>
#else
#include <stdio.h>
#include <string.h>
#define ALOGD printf
#define ALOGW printf
#endif

#ifdef HAVE_ANDROID_OS
/* SIOCKILLADDR is an Android extension. */
#define SIOCKILLADDR 0x8939
#endif

static int ifc_ctl_sock = -1;
static int ifc_ctl_sock6 = -1;
void printerr(char *fmt, ...);

#define DBG 0
#define INET_ADDRLEN 4
#define INET6_ADDRLEN 16

in_addr_t prefixLengthToIpv4Netmask(int prefix_length)
{
    in_addr_t mask = 0;

    // C99 (6.5.7): shifts of 32 bits have undefined results
    if (prefix_length <= 0 || prefix_length > 32) {
        return 0;
    }

    mask = ~mask << (32 - prefix_length);
    mask = htonl(mask);

    return mask;
}

int ipv4NetmaskToPrefixLength(in_addr_t mask)
{
    int prefixLength = 0;
    uint32_t m = (uint32_t)ntohl(mask);
    while (m & 0x80000000) {
        prefixLength++;
        m = m << 1;
    }
    return prefixLength;
}

static const char *ipaddr_to_string(in_addr_t addr)
{
    struct in_addr in_addr;

    in_addr.s_addr = addr;
    return inet_ntoa(in_addr);
}

int string_to_ip(const char *string, struct sockaddr_storage *ss) {
    struct addrinfo hints, *ai;
    int ret;

    if (ss == NULL) {
        return -EFAULT;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = AI_NUMERICHOST;
    hints.ai_socktype = SOCK_DGRAM;

    ret = getaddrinfo(string, NULL, &hints, &ai);
    if (ret == 0) {
        memcpy(ss, ai->ai_addr, ai->ai_addrlen);
        freeaddrinfo(ai);
    }

    return ret;
}

int ifc_init(void)
{
    int ret;
    if (ifc_ctl_sock == -1) {
        ifc_ctl_sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (ifc_ctl_sock < 0) {
            printerr("socket() failed: %s\n", strerror(errno));
        }
    }

    ret = ifc_ctl_sock < 0 ? -1 : 0;
    if (DBG) printerr("ifc_init_returning %d", ret);
    return ret;
}

int ifc_init6(void)
{
    if (ifc_ctl_sock6 == -1) {
        ifc_ctl_sock6 = socket(AF_INET6, SOCK_DGRAM, 0);
        if (ifc_ctl_sock6 < 0) {
            printerr("socket() failed: %s\n", strerror(errno));
        }
    }
    return ifc_ctl_sock6 < 0 ? -1 : 0;
}

void ifc_close(void)
{
    if (DBG) printerr("ifc_close");
    if (ifc_ctl_sock != -1) {
        (void)close(ifc_ctl_sock);
        ifc_ctl_sock = -1;
    }
}

void ifc_close6(void)
{
    if (ifc_ctl_sock6 != -1) {
        (void)close(ifc_ctl_sock6);
        ifc_ctl_sock6 = -1;
    }
}

static void ifc_init_ifr(const char *name, struct ifreq *ifr)
{
    memset(ifr, 0, sizeof(struct ifreq));
    strncpy(ifr->ifr_name, name, IFNAMSIZ);
    ifr->ifr_name[IFNAMSIZ - 1] = 0;
}

int ifc_get_hwaddr(const char *name, void *ptr)
{
    int r;
    struct ifreq ifr;
    ifc_init_ifr(name, &ifr);

    r = ioctl(ifc_ctl_sock, SIOCGIFHWADDR, &ifr);
    if(r < 0) return -1;

    memcpy(ptr, &ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    return 0;
}

int ifc_get_ifindex(const char *name, int *if_indexp)
{
    int r;
    struct ifreq ifr;
    ifc_init_ifr(name, &ifr);

    r = ioctl(ifc_ctl_sock, SIOCGIFINDEX, &ifr);
    if(r < 0) return -1;

    *if_indexp = ifr.ifr_ifindex;
    return 0;
}

static int ifc_set_flags(const char *name, unsigned set, unsigned clr)
{
    struct ifreq ifr;
    ifc_init_ifr(name, &ifr);

    if(ioctl(ifc_ctl_sock, SIOCGIFFLAGS, &ifr) < 0) return -1;
    ifr.ifr_flags = (ifr.ifr_flags & (~clr)) | set;
    return ioctl(ifc_ctl_sock, SIOCSIFFLAGS, &ifr);
}

int ifc_up(const char *name)
{
    int ret = ifc_set_flags(name, IFF_UP, 0);
    if (DBG) printerr("ifc_up(%s) = %d", name, ret);
    return ret;
}

int ifc_down(const char *name)
{
    int ret = ifc_set_flags(name, 0, IFF_UP);
    if (DBG) printerr("ifc_down(%s) = %d", name, ret);
    return ret;
}

static void init_sockaddr_in(struct sockaddr *sa, in_addr_t addr)
{
    struct sockaddr_in *sin = (struct sockaddr_in *) sa;
    sin->sin_family = AF_INET;
    sin->sin_port = 0;
    sin->sin_addr.s_addr = addr;
}

int ifc_set_addr(const char *name, in_addr_t addr)
{
    struct ifreq ifr;
    int ret;

    ifc_init_ifr(name, &ifr);
    init_sockaddr_in(&ifr.ifr_addr, addr);

    ret = ioctl(ifc_ctl_sock, SIOCSIFADDR, &ifr);
    if (DBG) printerr("ifc_set_addr(%s, xx) = %d", name, ret);
    return ret;
}

/*
 * Adds or deletes an IP address on an interface.
 *
 * Action is one of:
 * - RTM_NEWADDR (to add a new address)
 * - RTM_DELADDR (to delete an existing address)
 *
 * Returns zero on success and negative errno on failure.
 */
int ifc_act_on_address(int action, const char *name, const char *address,
                       int prefixlen) {
    int ifindex, s, len, ret;
    struct sockaddr_storage ss;
    void *addr;
    size_t addrlen;
    struct {
        struct nlmsghdr n;
        struct ifaddrmsg r;
        // Allow for IPv6 address, headers, and padding.
        char attrbuf[NLMSG_ALIGN(sizeof(struct nlmsghdr)) +
                     NLMSG_ALIGN(sizeof(struct rtattr)) +
                     NLMSG_ALIGN(INET6_ADDRLEN)];
    } req;
    struct rtattr *rta;
    struct nlmsghdr *nh;
    struct nlmsgerr *err;
    char buf[NLMSG_ALIGN(sizeof(struct nlmsghdr)) +
             NLMSG_ALIGN(sizeof(struct nlmsgerr)) +
             NLMSG_ALIGN(sizeof(struct nlmsghdr))];

    // Get interface ID.
    ifindex = if_nametoindex(name);
    if (ifindex == 0) {
        return -errno;
    }

    // Convert string representation to sockaddr_storage.
    ret = string_to_ip(address, &ss);
    if (ret) {
        return ret;
    }

    // Determine address type and length.
    if (ss.ss_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *) &ss;
        addr = &sin->sin_addr;
        addrlen = INET_ADDRLEN;
    } else if (ss.ss_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) &ss;
        addr = &sin6->sin6_addr;
        addrlen = INET6_ADDRLEN;
    } else {
        return -EAFNOSUPPORT;
    }

    // Fill in netlink structures.
    memset(&req, 0, sizeof(req));

    // Netlink message header.
    req.n.nlmsg_len = NLMSG_LENGTH(sizeof(req.r));
    req.n.nlmsg_type = action;
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    req.n.nlmsg_pid = getpid();

    // Interface address message header.
    req.r.ifa_family = ss.ss_family;
    req.r.ifa_prefixlen = prefixlen;
    req.r.ifa_index = ifindex;

    // Routing attribute. Contains the actual IP address.
    rta = (struct rtattr *) (((char *) &req) + NLMSG_ALIGN(req.n.nlmsg_len));
    rta->rta_type = IFA_LOCAL;
    rta->rta_len = RTA_LENGTH(addrlen);
    req.n.nlmsg_len = NLMSG_ALIGN(req.n.nlmsg_len) + RTA_LENGTH(addrlen);
    memcpy(RTA_DATA(rta), addr, addrlen);

    s = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (send(s, &req, req.n.nlmsg_len, 0) < 0) {
        close(s);
        return -errno;
    }

    len = recv(s, buf, sizeof(buf), 0);
    close(s);
    if (len < 0) {
        return -errno;
    }

    // Parse the acknowledgement to find the return code.
    nh = (struct nlmsghdr *) buf;
    if (!NLMSG_OK(nh, (unsigned) len) || nh->nlmsg_type != NLMSG_ERROR) {
        return -EINVAL;
    }
    err = NLMSG_DATA(nh);

    // Return code is negative errno.
    return err->error;
}

int ifc_add_address(const char *name, const char *address, int prefixlen) {
    return ifc_act_on_address(RTM_NEWADDR, name, address, prefixlen);
}

int ifc_del_address(const char *name, const char * address, int prefixlen) {
    return ifc_act_on_address(RTM_DELADDR, name, address, prefixlen);
}

/*
 * Clears IPv6 addresses on the specified interface.
 */
int ifc_clear_ipv6_addresses(const char *name) {
    char rawaddrstr[INET6_ADDRSTRLEN], addrstr[INET6_ADDRSTRLEN];
    unsigned int prefixlen;
    int lasterror = 0, i, j, ret;
    char ifname[64];  // Currently, IFNAMSIZ = 16.
    FILE *f = fopen("/proc/net/if_inet6", "r");
    if (!f) {
        return -errno;
    }

    // Format:
    // 20010db8000a0001fc446aa4b5b347ed 03 40 00 01    wlan0
    while (fscanf(f, "%32s %*02x %02x %*02x %*02x %63s\n",
                  rawaddrstr, &prefixlen, ifname) == 3) {
        // Is this the interface we're looking for?
        if (strcmp(name, ifname)) {
            continue;
        }

        // Put the colons back into the address.
        for (i = 0, j = 0; i < 32; i++, j++) {
            addrstr[j] = rawaddrstr[i];
            if (i % 4 == 3) {
                addrstr[++j] = ':';
            }
        }
        addrstr[j - 1] = '\0';

        // Don't delete the link-local address as well, or it will disable IPv6
        // on the interface.
        if (strncmp(addrstr, "fe80:", 5) == 0) {
            continue;
        }

        ret = ifc_del_address(ifname, addrstr, prefixlen);
        if (ret) {
            ALOGE("Deleting address %s/%d on %s: %s", addrstr, prefixlen, ifname,
                 strerror(-ret));
            lasterror = ret;
        }
    }

    fclose(f);
    return lasterror;
}

/*
 * Clears IPv4 addresses on the specified interface.
 */
void ifc_clear_ipv4_addresses(const char *name) {
    unsigned count, addr;
    ifc_init();
    for (count=0, addr=1;((addr != 0) && (count < 255)); count++) {
        if (ifc_get_addr(name, &addr) < 0)
            break;
        if (addr)
            ifc_set_addr(name, 0);
    }
    ifc_close();
}

/*
 * Clears all IP addresses on the specified interface.
 */
int ifc_clear_addresses(const char *name) {
    ifc_clear_ipv4_addresses(name);
    return ifc_clear_ipv6_addresses(name);
}

int ifc_set_hwaddr(const char *name, const void *ptr)
{
    int r;
    struct ifreq ifr;
    ifc_init_ifr(name, &ifr);

    ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
    memcpy(&ifr.ifr_hwaddr.sa_data, ptr, ETH_ALEN);
    return ioctl(ifc_ctl_sock, SIOCSIFHWADDR, &ifr);
}

int ifc_set_mask(const char *name, in_addr_t mask)
{
    struct ifreq ifr;
    int ret;

    ifc_init_ifr(name, &ifr);
    init_sockaddr_in(&ifr.ifr_addr, mask);

    ret = ioctl(ifc_ctl_sock, SIOCSIFNETMASK, &ifr);
    if (DBG) printerr("ifc_set_mask(%s, xx) = %d", name, ret);
    return ret;
}

int ifc_set_prefixLength(const char *name, int prefixLength)
{
    struct ifreq ifr;
    // TODO - support ipv6
    if (prefixLength > 32 || prefixLength < 0) return -1;

    in_addr_t mask = prefixLengthToIpv4Netmask(prefixLength);
    ifc_init_ifr(name, &ifr);
    init_sockaddr_in(&ifr.ifr_addr, mask);

    return ioctl(ifc_ctl_sock, SIOCSIFNETMASK, &ifr);
}

int ifc_get_addr(const char *name, in_addr_t *addr)
{
    struct ifreq ifr;
    int ret = 0;

    ifc_init_ifr(name, &ifr);
    if (addr != NULL) {
        ret = ioctl(ifc_ctl_sock, SIOCGIFADDR, &ifr);
        if (ret < 0) {
            *addr = 0;
        } else {
            *addr = ((struct sockaddr_in*) &ifr.ifr_addr)->sin_addr.s_addr;
        }
    }
    return ret;
}

int ifc_get_info(const char *name, in_addr_t *addr, int *prefixLength, unsigned *flags)
{
    struct ifreq ifr;
    ifc_init_ifr(name, &ifr);

    if (addr != NULL) {
        if(ioctl(ifc_ctl_sock, SIOCGIFADDR, &ifr) < 0) {
            *addr = 0;
        } else {
            *addr = ((struct sockaddr_in*) &ifr.ifr_addr)->sin_addr.s_addr;
        }
    }

    if (prefixLength != NULL) {
        if(ioctl(ifc_ctl_sock, SIOCGIFNETMASK, &ifr) < 0) {
            *prefixLength = 0;
        } else {
            *prefixLength = ipv4NetmaskToPrefixLength(
                    ((struct sockaddr_in*) &ifr.ifr_addr)->sin_addr.s_addr);
        }
    }

    if (flags != NULL) {
        if(ioctl(ifc_ctl_sock, SIOCGIFFLAGS, &ifr) < 0) {
            *flags = 0;
        } else {
            *flags = ifr.ifr_flags;
        }
    }

    return 0;
}

int ifc_act_on_ipv4_route(int action, const char *ifname, struct in_addr dst, int prefix_length,
      struct in_addr gw)
{
    struct rtentry rt;
    int result;
    in_addr_t netmask;

    memset(&rt, 0, sizeof(rt));

    rt.rt_dst.sa_family = AF_INET;
    rt.rt_dev = (void*) ifname;

    netmask = prefixLengthToIpv4Netmask(prefix_length);
    init_sockaddr_in(&rt.rt_genmask, netmask);
    init_sockaddr_in(&rt.rt_dst, dst.s_addr);
    rt.rt_flags = RTF_UP;

    if (prefix_length == 32) {
        rt.rt_flags |= RTF_HOST;
    }

    if (gw.s_addr != 0) {
        rt.rt_flags |= RTF_GATEWAY;
        init_sockaddr_in(&rt.rt_gateway, gw.s_addr);
    }

    ifc_init();

    if (ifc_ctl_sock < 0) {
        return -errno;
    }

    result = ioctl(ifc_ctl_sock, action, &rt);
    if (result < 0) {
        if (errno == EEXIST) {
            result = 0;
        } else {
            result = -errno;
        }
    }
    ifc_close();
    return result;
}

/* deprecated - v4 only */
int ifc_create_default_route(const char *name, in_addr_t gw)
{
    struct in_addr in_dst, in_gw;

    in_dst.s_addr = 0;
    in_gw.s_addr = gw;

    int ret = ifc_act_on_ipv4_route(SIOCADDRT, name, in_dst, 0, in_gw);
    if (DBG) printerr("ifc_create_default_route(%s, %d) = %d", name, gw, ret);
    return ret;
}

/* deprecated v4-only */
int ifc_add_host_route(const char *name, in_addr_t dst)
{
    struct in_addr in_dst, in_gw;

    in_dst.s_addr = dst;
    in_gw.s_addr = 0;

    return ifc_act_on_ipv4_route(SIOCADDRT, name, in_dst, 32, in_gw);
}

int ifc_enable(const char *ifname)
{
    int result;

    ifc_init();
    result = ifc_up(ifname);
    ifc_close();
    return result;
}

int ifc_disable(const char *ifname)
{
    unsigned addr, count;
    int result;

    ifc_init();
    result = ifc_down(ifname);

    ifc_set_addr(ifname, 0);
    for (count=0, addr=1;((addr != 0) && (count < 255)); count++) {
       if (ifc_get_addr(ifname, &addr) < 0)
            break;
       if (addr)
          ifc_set_addr(ifname, 0);
    }

    ifc_close();
    return result;
}

int ifc_reset_connections(const char *ifname, const int reset_mask)
{
#ifdef HAVE_ANDROID_OS
    int result, success;
    in_addr_t myaddr;
    struct ifreq ifr;
    struct in6_ifreq ifr6;

    if (reset_mask & RESET_IPV4_ADDRESSES) {
        /* IPv4. Clear connections on the IP address. */
        ifc_init();
        ifc_get_info(ifname, &myaddr, NULL, NULL);
        ifc_init_ifr(ifname, &ifr);
        init_sockaddr_in(&ifr.ifr_addr, myaddr);
        result = ioctl(ifc_ctl_sock, SIOCKILLADDR,  &ifr);
        ifc_close();
    } else {
        result = 0;
    }

    if (reset_mask & RESET_IPV6_ADDRESSES) {
        /*
         * IPv6. On Linux, when an interface goes down it loses all its IPv6
         * addresses, so we don't know which connections belonged to that interface
         * So we clear all unused IPv6 connections on the device by specifying an
         * empty IPv6 address.
         */
        ifc_init6();
        // This implicitly specifies an address of ::, i.e., kill all IPv6 sockets.
        memset(&ifr6, 0, sizeof(ifr6));
        success = ioctl(ifc_ctl_sock6, SIOCKILLADDR,  &ifr6);
        if (result == 0) {
            result = success;
        }
        ifc_close6();
    }

    return result;
#else
    return 0;
#endif
}

/*
 * Remove the routes associated with the named interface.
 */
int ifc_remove_host_routes(const char *name)
{
    char ifname[64];
    in_addr_t dest, gway, mask;
    int flags, refcnt, use, metric, mtu, win, irtt;
    struct rtentry rt;
    FILE *fp;
    struct in_addr addr;

    fp = fopen("/proc/net/route", "r");
    if (fp == NULL)
        return -1;
    /* Skip the header line */
    if (fscanf(fp, "%*[^\n]\n") < 0) {
        fclose(fp);
        return -1;
    }
    ifc_init();
    for (;;) {
        int nread = fscanf(fp, "%63s%X%X%X%d%d%d%X%d%d%d\n",
                           ifname, &dest, &gway, &flags, &refcnt, &use, &metric, &mask,
                           &mtu, &win, &irtt);
        if (nread != 11) {
            break;
        }
        if ((flags & (RTF_UP|RTF_HOST)) != (RTF_UP|RTF_HOST)
                || strcmp(ifname, name) != 0) {
            continue;
        }
        memset(&rt, 0, sizeof(rt));
        rt.rt_dev = (void *)name;
        init_sockaddr_in(&rt.rt_dst, dest);
        init_sockaddr_in(&rt.rt_gateway, gway);
        init_sockaddr_in(&rt.rt_genmask, mask);
        addr.s_addr = dest;
        if (ioctl(ifc_ctl_sock, SIOCDELRT, &rt) < 0) {
            ALOGD("failed to remove route for %s to %s: %s",
                 ifname, inet_ntoa(addr), strerror(errno));
        }
    }
    fclose(fp);
    ifc_close();
    return 0;
}

/*
 * Return the address of the default gateway
 *
 * TODO: factor out common code from this and remove_host_routes()
 * so that we only scan /proc/net/route in one place.
 *
 * DEPRECATED
 */
int ifc_get_default_route(const char *ifname)
{
    char name[64];
    in_addr_t dest, gway, mask;
    int flags, refcnt, use, metric, mtu, win, irtt;
    int result;
    FILE *fp;

    fp = fopen("/proc/net/route", "r");
    if (fp == NULL)
        return 0;
    /* Skip the header line */
    if (fscanf(fp, "%*[^\n]\n") < 0) {
        fclose(fp);
        return 0;
    }
    ifc_init();
    result = 0;
    for (;;) {
        int nread = fscanf(fp, "%63s%X%X%X%d%d%d%X%d%d%d\n",
                           name, &dest, &gway, &flags, &refcnt, &use, &metric, &mask,
                           &mtu, &win, &irtt);
        if (nread != 11) {
            break;
        }
        if ((flags & (RTF_UP|RTF_GATEWAY)) == (RTF_UP|RTF_GATEWAY)
                && dest == 0
                && strcmp(ifname, name) == 0) {
            result = gway;
            break;
        }
    }
    fclose(fp);
    ifc_close();
    return result;
}

/*
 * Sets the specified gateway as the default route for the named interface.
 * DEPRECATED
 */
int ifc_set_default_route(const char *ifname, in_addr_t gateway)
{
    struct in_addr addr;
    int result;

    ifc_init();
    addr.s_addr = gateway;
    if ((result = ifc_create_default_route(ifname, gateway)) < 0) {
        ALOGD("failed to add %s as default route for %s: %s",
             inet_ntoa(addr), ifname, strerror(errno));
    }
    ifc_close();
    return result;
}

/*
 * Removes the default route for the named interface.
 */
int ifc_remove_default_route(const char *ifname)
{
    struct rtentry rt;
    int result;

    ifc_init();
    memset(&rt, 0, sizeof(rt));
    rt.rt_dev = (void *)ifname;
    rt.rt_flags = RTF_UP|RTF_GATEWAY;
    init_sockaddr_in(&rt.rt_dst, 0);
    if ((result = ioctl(ifc_ctl_sock, SIOCDELRT, &rt)) < 0) {
        ALOGD("failed to remove default route for %s: %s", ifname, strerror(errno));
    }
    ifc_close();
    return result;
}

int
ifc_configure(const char *ifname,
        in_addr_t address,
        uint32_t prefixLength,
        in_addr_t gateway,
        in_addr_t dns1,
        in_addr_t dns2) {

    char dns_prop_name[PROPERTY_KEY_MAX];

    ifc_init();

    if (ifc_up(ifname)) {
        printerr("failed to turn on interface %s: %s\n", ifname, strerror(errno));
        ifc_close();
        return -1;
    }
    if (ifc_set_addr(ifname, address)) {
        printerr("failed to set ipaddr %s: %s\n", ipaddr_to_string(address), strerror(errno));
        ifc_close();
        return -1;
    }
    if (ifc_set_prefixLength(ifname, prefixLength)) {
        printerr("failed to set prefixLength %d: %s\n", prefixLength, strerror(errno));
        ifc_close();
        return -1;
    }
    if (ifc_create_default_route(ifname, gateway)) {
        printerr("failed to set default route %s: %s\n", ipaddr_to_string(gateway), strerror(errno));
        ifc_close();
        return -1;
    }

    ifc_close();

    snprintf(dns_prop_name, sizeof(dns_prop_name), "net.%s.dns1", ifname);
    property_set(dns_prop_name, dns1 ? ipaddr_to_string(dns1) : "");
    snprintf(dns_prop_name, sizeof(dns_prop_name), "net.%s.dns2", ifname);
    property_set(dns_prop_name, dns2 ? ipaddr_to_string(dns2) : "");

    return 0;
}

int ifc_act_on_ipv6_route(int action, const char *ifname, struct in6_addr dst, int prefix_length,
      struct in6_addr gw)
{
    struct in6_rtmsg rtmsg;
    int result;
    int ifindex;

    memset(&rtmsg, 0, sizeof(rtmsg));

    ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        printerr("if_nametoindex() failed: interface %s\n", ifname);
        return -ENXIO;
    }

    rtmsg.rtmsg_ifindex = ifindex;
    rtmsg.rtmsg_dst = dst;
    rtmsg.rtmsg_dst_len = prefix_length;
    rtmsg.rtmsg_flags = RTF_UP;

    if (prefix_length == 128) {
        rtmsg.rtmsg_flags |= RTF_HOST;
    }

    if (memcmp(&gw, &in6addr_any, sizeof(in6addr_any))) {
        rtmsg.rtmsg_flags |= RTF_GATEWAY;
        rtmsg.rtmsg_gateway = gw;
    }

    ifc_init6();

    if (ifc_ctl_sock6 < 0) {
        return -errno;
    }

    result = ioctl(ifc_ctl_sock6, action, &rtmsg);
    if (result < 0) {
        if (errno == EEXIST) {
            result = 0;
        } else {
            result = -errno;
        }
    }
    ifc_close6();
    return result;
}

int ifc_act_on_route(int action, const char *ifname, const char *dst, int prefix_length,
        const char *gw)
{
    int ret = 0;
    struct sockaddr_in ipv4_dst, ipv4_gw;
    struct sockaddr_in6 ipv6_dst, ipv6_gw;
    struct addrinfo hints, *addr_ai, *gw_ai;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;  /* Allow IPv4 or IPv6 */
    hints.ai_flags = AI_NUMERICHOST;

    ret = getaddrinfo(dst, NULL, &hints, &addr_ai);

    if (ret != 0) {
        printerr("getaddrinfo failed: invalid address %s\n", dst);
        return -EINVAL;
    }

    if (gw == NULL || (strlen(gw) == 0)) {
        if (addr_ai->ai_family == AF_INET6) {
            gw = "::";
        } else if (addr_ai->ai_family == AF_INET) {
            gw = "0.0.0.0";
        }
    }

    if (((addr_ai->ai_family == AF_INET6) && (prefix_length < 0 || prefix_length > 128)) ||
            ((addr_ai->ai_family == AF_INET) && (prefix_length < 0 || prefix_length > 32))) {
        printerr("ifc_add_route: invalid prefix length");
        freeaddrinfo(addr_ai);
        return -EINVAL;
    }

    ret = getaddrinfo(gw, NULL, &hints, &gw_ai);
    if (ret != 0) {
        printerr("getaddrinfo failed: invalid gateway %s\n", gw);
        freeaddrinfo(addr_ai);
        return -EINVAL;
    }

    if (addr_ai->ai_family != gw_ai->ai_family) {
        printerr("ifc_add_route: different address families: %s and %s\n", dst, gw);
        freeaddrinfo(addr_ai);
        freeaddrinfo(gw_ai);
        return -EINVAL;
    }

    if (addr_ai->ai_family == AF_INET6) {
        memcpy(&ipv6_dst, addr_ai->ai_addr, sizeof(struct sockaddr_in6));
        memcpy(&ipv6_gw, gw_ai->ai_addr, sizeof(struct sockaddr_in6));
        ret = ifc_act_on_ipv6_route(action, ifname, ipv6_dst.sin6_addr,
                prefix_length, ipv6_gw.sin6_addr);
    } else if (addr_ai->ai_family == AF_INET) {
        memcpy(&ipv4_dst, addr_ai->ai_addr, sizeof(struct sockaddr_in));
        memcpy(&ipv4_gw, gw_ai->ai_addr, sizeof(struct sockaddr_in));
        ret = ifc_act_on_ipv4_route(action, ifname, ipv4_dst.sin_addr,
                prefix_length, ipv4_gw.sin_addr);
    } else {
        printerr("ifc_add_route: getaddrinfo returned un supported address family %d\n",
                  addr_ai->ai_family);
        ret = -EAFNOSUPPORT;
    }

    freeaddrinfo(addr_ai);
    freeaddrinfo(gw_ai);
    return ret;
}

/*
 * DEPRECATED
 */
int ifc_add_ipv4_route(const char *ifname, struct in_addr dst, int prefix_length,
      struct in_addr gw)
{
    int i =ifc_act_on_ipv4_route(SIOCADDRT, ifname, dst, prefix_length, gw);
    if (DBG) printerr("ifc_add_ipv4_route(%s, xx, %d, xx) = %d", ifname, prefix_length, i);
    return i;
}

/*
 * DEPRECATED
 */
int ifc_add_ipv6_route(const char *ifname, struct in6_addr dst, int prefix_length,
      struct in6_addr gw)
{
    return ifc_act_on_ipv6_route(SIOCADDRT, ifname, dst, prefix_length, gw);
}

int ifc_add_route(const char *ifname, const char *dst, int prefix_length, const char *gw)
{
    int i = ifc_act_on_route(SIOCADDRT, ifname, dst, prefix_length, gw);
    if (DBG) printerr("ifc_add_route(%s, %s, %d, %s) = %d", ifname, dst, prefix_length, gw, i);
    return i;
}

int ifc_remove_route(const char *ifname, const char*dst, int prefix_length, const char *gw)
{
    return ifc_act_on_route(SIOCDELRT, ifname, dst, prefix_length, gw);
}

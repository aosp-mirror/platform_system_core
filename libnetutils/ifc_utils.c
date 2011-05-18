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

#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/sockios.h>
#include <linux/route.h>
#include <linux/ipv6_route.h>
#include <netdb.h>
#include <linux/wireless.h>

#ifdef ANDROID
#define LOG_TAG "NetUtils"
#include <cutils/log.h>
#include <cutils/properties.h>
#else
#include <stdio.h>
#include <string.h>
#define LOGD printf
#define LOGW printf
#endif

static int ifc_ctl_sock = -1;
static int ifc_ctl_sock6 = -1;
void printerr(char *fmt, ...);

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
    mask = ntohl(mask);
    int prefixLength = 0;
    uint32_t m = (uint32_t)mask;
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

int ifc_init(void)
{
    if (ifc_ctl_sock == -1) {
        ifc_ctl_sock = socket(AF_INET, SOCK_DGRAM, 0);    
        if (ifc_ctl_sock < 0) {
            printerr("socket() failed: %s\n", strerror(errno));
        }
    }
    return ifc_ctl_sock < 0 ? -1 : 0;
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
    return ifc_set_flags(name, IFF_UP, 0);
}

int ifc_down(const char *name)
{
    return ifc_set_flags(name, 0, IFF_UP);
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

    ifc_init_ifr(name, &ifr);
    init_sockaddr_in(&ifr.ifr_addr, addr);

    return ioctl(ifc_ctl_sock, SIOCSIFADDR, &ifr);
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
            *prefixLength = ipv4NetmaskToPrefixLength((int)
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

int ifc_create_default_route(const char *name, in_addr_t gw)
{
    struct in_addr in_dst, in_gw;

    in_dst.s_addr = 0;
    in_gw.s_addr = gw;

    return ifc_act_on_route(SIOCADDRT, name, in_dst, 0, in_gw);
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

int ifc_reset_connections(const char *ifname)
{
#ifdef HAVE_ANDROID_OS
    int result, success;
    in_addr_t myaddr;
    struct ifreq ifr;
    struct in6_ifreq ifr6;

    /* IPv4. Clear connections on the IP address. */
    ifc_init();
    ifc_get_info(ifname, &myaddr, NULL, NULL);
    ifc_init_ifr(ifname, &ifr);
    init_sockaddr_in(&ifr.ifr_addr, myaddr);
    result = ioctl(ifc_ctl_sock, SIOCKILLADDR,  &ifr);
    ifc_close();

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
            LOGD("failed to remove route for %s to %s: %s",
                 ifname, inet_ntoa(addr), strerror(errno));
        }
    }
    fclose(fp);
    ifc_close();
    return 0;
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
        LOGD("failed to remove default route for %s: %s", ifname, strerror(errno));
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

int ifc_add_route(const char *ifname, const char *dst, int prefix_length, const char *gw)
{
    return ifc_act_on_route(SIOCADDRT, ifname, dst, prefix_length, gw);
}

int ifc_remove_route(const char *ifname, const char*dst, int prefix_length, const char *gw)
{
    return ifc_act_on_route(SIOCDELRT, ifname, dst, prefix_length, gw);
}

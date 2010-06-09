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

#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/sockios.h>
#include <linux/route.h>
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
void printerr(char *fmt, ...);

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

void ifc_close(void)
{
    if (ifc_ctl_sock != -1) {
        (void)close(ifc_ctl_sock);
        ifc_ctl_sock = -1;
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

int ifc_set_mask(const char *name, in_addr_t mask)
{
    struct ifreq ifr;

    ifc_init_ifr(name, &ifr);
    init_sockaddr_in(&ifr.ifr_addr, mask);
    
    return ioctl(ifc_ctl_sock, SIOCSIFNETMASK, &ifr);
}

int ifc_get_info(const char *name, in_addr_t *addr, in_addr_t *mask, unsigned *flags)
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
    
    if (mask != NULL) {
        if(ioctl(ifc_ctl_sock, SIOCGIFNETMASK, &ifr) < 0) {
            *mask = 0;
        } else {
            *mask = ((struct sockaddr_in*) &ifr.ifr_addr)->sin_addr.s_addr;
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


int ifc_create_default_route(const char *name, in_addr_t addr)
{
    struct rtentry rt;

    memset(&rt, 0, sizeof(rt));
    
    rt.rt_dst.sa_family = AF_INET;
    rt.rt_flags = RTF_UP | RTF_GATEWAY;
    rt.rt_dev = (void*) name;
    init_sockaddr_in(&rt.rt_genmask, 0);
    init_sockaddr_in(&rt.rt_gateway, addr);
    
    return ioctl(ifc_ctl_sock, SIOCADDRT, &rt);
}

int ifc_add_host_route(const char *name, in_addr_t addr)
{
    struct rtentry rt;
    int result;

    memset(&rt, 0, sizeof(rt));
    
    rt.rt_dst.sa_family = AF_INET;
    rt.rt_flags = RTF_UP | RTF_HOST;
    rt.rt_dev = (void*) name;
    init_sockaddr_in(&rt.rt_dst, addr);
    init_sockaddr_in(&rt.rt_genmask, 0);
    init_sockaddr_in(&rt.rt_gateway, 0);
    
    ifc_init();
    result = ioctl(ifc_ctl_sock, SIOCADDRT, &rt);
    if (result < 0 && errno == EEXIST) {
        result = 0;
    }
    ifc_close();
    return result;
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
    int result;

    ifc_init();
    result = ifc_down(ifname);
    ifc_set_addr(ifname, 0);
    ifc_close();
    return result;
}

int ifc_reset_connections(const char *ifname)
{
#ifdef HAVE_ANDROID_OS
    int result;
    in_addr_t myaddr;
    struct ifreq ifr;

    ifc_init();
    ifc_get_info(ifname, &myaddr, NULL, NULL);
    ifc_init_ifr(ifname, &ifr);
    init_sockaddr_in(&ifr.ifr_addr, myaddr);
    result = ioctl(ifc_ctl_sock, SIOCKILLADDR,  &ifr);
    ifc_close();
    
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
 * Return the address of the default gateway
 *
 * TODO: factor out common code from this and remove_host_routes()
 * so that we only scan /proc/net/route in one place.
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
 */
int ifc_set_default_route(const char *ifname, in_addr_t gateway)
{
    struct in_addr addr;
    int result;

    ifc_init();
    addr.s_addr = gateway;
    if ((result = ifc_create_default_route(ifname, gateway)) < 0) {
        LOGD("failed to add %s as default route for %s: %s",
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
        LOGD("failed to remove default route for %s: %s", ifname, strerror(errno));
    }
    ifc_close();
    return result;
}

int
ifc_configure(const char *ifname,
        in_addr_t address,
        in_addr_t netmask,
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
    if (ifc_set_mask(ifname, netmask)) {
        printerr("failed to set netmask %s: %s\n", ipaddr_to_string(netmask), strerror(errno));
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

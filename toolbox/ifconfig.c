
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <errno.h>
#include <string.h>
#include <ctype.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <linux/sockios.h>
#include <arpa/inet.h>

static void die(const char *s)
{
    fprintf(stderr,"error: %s (%s)\n", s, strerror(errno));
    exit(-1);
}

static void setflags(int s, struct ifreq *ifr, int set, int clr)
{
    if(ioctl(s, SIOCGIFFLAGS, ifr) < 0) die("SIOCGIFFLAGS");
    ifr->ifr_flags = (ifr->ifr_flags & (~clr)) | set;
    if(ioctl(s, SIOCSIFFLAGS, ifr) < 0) die("SIOCSIFFLAGS");
}

static inline void init_sockaddr_in(struct sockaddr_in *sin, const char *addr)
{
    sin->sin_family = AF_INET;
    sin->sin_port = 0;
    sin->sin_addr.s_addr = inet_addr(addr);
}

static void setmtu(int s, struct ifreq *ifr, const char *mtu)
{
    int m = atoi(mtu);
    ifr->ifr_mtu = m;
    if(ioctl(s, SIOCSIFMTU, ifr) < 0) die("SIOCSIFMTU");
}
static void setdstaddr(int s, struct ifreq *ifr, const char *addr)
{
    init_sockaddr_in((struct sockaddr_in *) &ifr->ifr_dstaddr, addr);
    if(ioctl(s, SIOCSIFDSTADDR, ifr) < 0) die("SIOCSIFDSTADDR");
}

static void setnetmask(int s, struct ifreq *ifr, const char *addr)
{
    init_sockaddr_in((struct sockaddr_in *) &ifr->ifr_netmask, addr);
    if(ioctl(s, SIOCSIFNETMASK, ifr) < 0) die("SIOCSIFNETMASK");
}

static void setaddr(int s, struct ifreq *ifr, const char *addr)
{
    init_sockaddr_in((struct sockaddr_in *) &ifr->ifr_addr, addr);
    if(ioctl(s, SIOCSIFADDR, ifr) < 0) die("SIOCSIFADDR");
}

int ifconfig_main(int argc, char *argv[])
{
    struct ifreq ifr;
    int s;
    unsigned int addr, mask, flags;
    char astring[20];
    char mstring[20];
    char *updown, *brdcst, *loopbk, *ppp, *running, *multi;
    
    argc--;
    argv++;

    if(argc == 0) return 0;

    memset(&ifr, 0, sizeof(struct ifreq));
    strncpy(ifr.ifr_name, argv[0], IFNAMSIZ);
    ifr.ifr_name[IFNAMSIZ-1] = 0;
    argc--, argv++;

    if((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        die("cannot open control socket\n");
    }

    if (argc == 0) {
        if (ioctl(s, SIOCGIFADDR, &ifr) < 0) {
            perror(ifr.ifr_name);
            return -1;
        } else
            addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;

        if (ioctl(s, SIOCGIFNETMASK, &ifr) < 0) {
            perror(ifr.ifr_name);
            return -1;
        } else
            mask = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;

        if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0) {
            perror(ifr.ifr_name);
            return -1;
        } else
            flags = ifr.ifr_flags;

        sprintf(astring, "%d.%d.%d.%d",
                addr & 0xff,
                ((addr >> 8) & 0xff),
                ((addr >> 16) & 0xff),
                ((addr >> 24) & 0xff));
        sprintf(mstring, "%d.%d.%d.%d",
                mask & 0xff,
                ((mask >> 8) & 0xff),
                ((mask >> 16) & 0xff),
                ((mask >> 24) & 0xff));
        printf("%s: ip %s mask %s flags [", ifr.ifr_name,
               astring,
               mstring
               );

        updown =  (flags & IFF_UP)           ? "up" : "down";
        brdcst =  (flags & IFF_BROADCAST)    ? " broadcast" : "";
        loopbk =  (flags & IFF_LOOPBACK)     ? " loopback" : "";
        ppp =     (flags & IFF_POINTOPOINT)  ? " point-to-point" : "";
        running = (flags & IFF_RUNNING)      ? " running" : "";
        multi =   (flags & IFF_MULTICAST)    ? " multicast" : "";
        printf("%s%s%s%s%s%s]\n", updown, brdcst, loopbk, ppp, running, multi);
        return 0;
    }
    
    while(argc > 0) {
        if (!strcmp(argv[0], "up")) {
            setflags(s, &ifr, IFF_UP, 0);
        } else if (!strcmp(argv[0], "mtu")) {
            argc--, argv++;
            if (!argc) {
                errno = EINVAL;
                die("expecting a value for parameter \"mtu\"");
            }
            setmtu(s, &ifr, argv[0]);
        } else if (!strcmp(argv[0], "-pointopoint")) {
            setflags(s, &ifr, IFF_POINTOPOINT, 1);
        } else if (!strcmp(argv[0], "pointopoint")) {
            argc--, argv++;
            if (!argc) { 
                errno = EINVAL;
                die("expecting an IP address for parameter \"pointtopoint\"");
            }
            setdstaddr(s, &ifr, argv[0]);
            setflags(s, &ifr, IFF_POINTOPOINT, 0);
        } else if (!strcmp(argv[0], "down")) {
            setflags(s, &ifr, 0, IFF_UP);
        } else if (!strcmp(argv[0], "netmask")) {
            argc--, argv++;
            if (!argc) { 
                errno = EINVAL;
                die("expecting an IP address for parameter \"netmask\"");
            }
            setnetmask(s, &ifr, argv[0]);
        } else if (isdigit(argv[0][0])) {
            setaddr(s, &ifr, argv[0]);
            setflags(s, &ifr, IFF_UP, 0);
        }
        argc--, argv++;
    }
    return 0;
}

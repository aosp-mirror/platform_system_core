
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>

#include <errno.h>
#include <string.h>
#include <ctype.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <linux/sockios.h>
#include <arpa/inet.h>
#include <linux/route.h>

static void die(const char *fmt, ...)
{
    va_list p;

    va_start(p, fmt);
    fprintf(stderr,"error(%s): ", strerror(errno));
    fprintf(stderr, fmt, p);
    va_end(p);
    exit(-1);
}

static inline void init_sockaddr_in(struct sockaddr_in *sin, const char *addr)
{
	sin->sin_family = AF_INET;
	sin->sin_port = 0;
	sin->sin_addr.s_addr = inet_addr(addr);
}

#define ADVANCE(argc, argv) do { argc--, argv++; } while(0)
#define EXPECT_NEXT(argc, argv) do {        \
    ADVANCE(argc, argv);                    \
	if (0 == argc) {  						\
		errno = EINVAL;                     \
		die("expecting one more argument"); \
	}                                       \
} while(0)		

/* current support the following routing entries */
/* route add default dev wlan0 */
/* route add default gw 192.168.20.1 dev wlan0 */
/* route add net 192.168.1.1 netmask 255.255.255.0 gw 172.24.192.10 */

int route_main(int argc, char *argv[])
{
    struct ifreq ifr;
    int s,i;
	struct rtentry rt;
	struct sockaddr_in ina;
   
    if(argc == 0) return 0;
    
    strncpy(ifr.ifr_name, argv[0], IFNAMSIZ);
    ifr.ifr_name[IFNAMSIZ-1] = 0;
	ADVANCE(argc, argv);

    if((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        die("cannot open control socket\n");
    }

    while(argc > 0){
        if(!strcmp(argv[0], "add")) {
			EXPECT_NEXT(argc, argv);
			if(!strcmp(argv[0], "default")) {
				EXPECT_NEXT(argc, argv);
				memset((char *) &rt, 0, sizeof(struct rtentry));
				rt.rt_dst.sa_family = AF_INET;	
				if(!strcmp(argv[0], "dev")) {
				  EXPECT_NEXT(argc, argv);
				  rt.rt_flags = RTF_UP | RTF_HOST;
				  rt.rt_dev = argv[0];
				  if (ioctl(s, SIOCADDRT, &rt) < 0) die("SIOCADDRT\n");
				}else if(!strcmp(argv[0], "gw")) {
				  EXPECT_NEXT(argc, argv);
				  rt.rt_flags = RTF_UP | RTF_GATEWAY;
				  init_sockaddr_in((struct sockaddr_in *)&(rt.rt_genmask), "0.0.0.0");
				  if(isdigit(argv[0][0])){
					init_sockaddr_in((struct sockaddr_in *)&(rt.rt_gateway), argv[0]);
				  }else{
					die("expecting an IP address for parameter \"gw\"\n");
				  }
				  EXPECT_NEXT(argc, argv);
				  if(!strcmp(argv[0], "dev")) {
					EXPECT_NEXT(argc, argv);
					rt.rt_dev = argv[0];
					if (ioctl(s, SIOCADDRT, &rt) < 0){
					  die("SIOCADDRT\n");
					}
				  }
				}
			} else  {
                          char keywords[3][5] = { "net", "mask", "gw" };
                          struct sockaddr_in *paddr[3] = { &rt.rt_dst, &rt.rt_genmask, &rt.rt_gateway };
                          int k = 0;

                          memset((char *) &rt, 0, sizeof(struct rtentry));
                          rt.rt_flags = RTF_UP | RTF_GATEWAY;
                          do {
                            if(!strcmp(argv[0], keywords[k])) {
                              EXPECT_NEXT(argc, argv);
                              if(isdigit(argv[0][0])) {
                                init_sockaddr_in(paddr[k], argv[0]);
                              } else {
                                die("expecting an IP/MASK address for parameter %s\n", keywords[k]);
                              }
                              if(k < 2) EXPECT_NEXT(argc, argv);
                            } else {
                              die("expecting keyword(s)\n");
                            }
                          } while(++k < 3);
                          if(ioctl(s, SIOCADDRT, &rt) < 0) {
                            die("SIOCADDRT\n");
                          }
                        }
        }
		ADVANCE(argc, argv);
    }

    return 0;
}

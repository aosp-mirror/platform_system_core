/*
 * Copyright (c) 2009, The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *  * Neither the name of Google, Inc. nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/route.h>

static inline int set_address(const char *address, struct sockaddr *sa) {
    return inet_aton(address, &((struct sockaddr_in *)sa)->sin_addr);
}

/* current support the following routing entries */
/* route add default dev wlan0 */
/* route add default gw 192.168.1.1 dev wlan0 */
/* route add -net 192.168.1.2 netmask 255.255.255.0 gw 192.168.1.1 */

int route_main(int argc, char *argv[])
{
    struct rtentry rt = {
        .rt_dst     = {.sa_family = AF_INET},
        .rt_genmask = {.sa_family = AF_INET},
        .rt_gateway = {.sa_family = AF_INET},
    };

    errno = EINVAL;
    if (argc > 2 && !strcmp(argv[1], "add")) {
        if (!strcmp(argv[2], "default")) {
            /* route add default dev wlan0 */
            if (argc > 4 && !strcmp(argv[3], "dev")) {
                rt.rt_flags = RTF_UP | RTF_HOST;
                rt.rt_dev = argv[4];
                errno = 0;
                goto apply;
            }

            /* route add default gw 192.168.1.1 dev wlan0 */
            if (argc > 6 && !strcmp(argv[3], "gw") && !strcmp(argv[5], "dev")) {
                rt.rt_flags = RTF_UP | RTF_GATEWAY;
                rt.rt_dev = argv[6];
                if (set_address(argv[4], &rt.rt_gateway)) {
                    errno = 0;
                }
                goto apply;
            }
        }

        /* route add -net 192.168.1.2 netmask 255.255.255.0 gw 192.168.1.1 */
        if (argc > 7 && !strcmp(argv[2], "-net") &&
            !strcmp(argv[4], "netmask") && !strcmp(argv[6], "gw")) {
            rt.rt_flags = RTF_UP | RTF_GATEWAY;
            if (set_address(argv[3], &rt.rt_dst) &&
                set_address(argv[5], &rt.rt_genmask) &&
                set_address(argv[7], &rt.rt_gateway)) {
                errno = 0;
            }
            goto apply;
        }
    }

apply:
    if (!errno) {
        int s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s != -1 && (ioctl(s, SIOCADDRT, &rt) != -1 || errno == EEXIST)) {
            return 0;
        }
    }
    puts(strerror(errno));
    return errno;
}

/*
 * Copyright (c) 2008, The Android Open Source Project
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

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>

#define PROC_NET_DEV    "/proc/net/dev"

#define MAX_IF           8   /* max interfaces we can handle */

#ifndef PAGE_SIZE
# define PAGE_SIZE 4096
#endif

#define _STR(s) #s
#define STR(s) _STR(s)

struct if_stats {
    char name[IFNAMSIZ];

    unsigned int mtu;

    unsigned int rx_bytes;
    unsigned int rx_packets;
    unsigned int rx_errors;
    unsigned int rx_dropped;

    unsigned int tx_bytes;
    unsigned int tx_packets;
    unsigned int tx_errors;
    unsigned int tx_dropped;
};

static int get_mtu(const char *if_name)
{
    struct ifreq ifr;
    int s, ret;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    memset(&ifr, 0, sizeof(struct ifreq));
    ifr.ifr_addr.sa_family = AF_INET;
    strcpy(ifr.ifr_name, if_name);

    ret = ioctl(s, SIOCGIFMTU, &ifr);
    if (ret < 0) {
        perror("ioctl");
        exit(EXIT_FAILURE);
    }

    ret = close(s);
    if (ret < 0) {
        perror("close");
        exit(EXIT_FAILURE);
    }

    return ifr.ifr_mtu;
}

static int get_interfaces(struct if_stats *ifs)
{
    char buf[PAGE_SIZE];
    char *p;
    int ret, nr, fd;

    fd = open(PROC_NET_DEV, O_RDONLY);
    if (fd < 0) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    ret = read(fd, buf, sizeof(buf) - 1);
    if (ret < 0) {
        perror("read");
        exit(EXIT_FAILURE);
    } else if (!ret) {
        fprintf(stderr, "reading " PROC_NET_DEV " returned premature EOF\n");
        exit(EXIT_FAILURE);
    }
    buf[ret] = '\0';

    /* skip down to the third line */
    p = strchr(buf, '\n');
    if (!p) {
        fprintf(stderr, "parsing " PROC_NET_DEV " failed unexpectedly\n");
        exit(EXIT_FAILURE);
    }
    p = strchr(p + 1, '\n');
    if (!p) {
        fprintf(stderr, "parsing " PROC_NET_DEV " failed unexpectedly\n");
        exit(EXIT_FAILURE);
    }
    p += 1;

    /*
     * Key:
     * if: (Rx) bytes packets errs drop fifo frame compressed multicast \
     *     (Tx) bytes packets errs drop fifo colls carrier compressed
     */
    for (nr = 0; nr < MAX_IF; nr++) {
        char *c;

        ret = sscanf(p, "%" STR(IFNAMSIZ) "s", ifs->name);
        if (ret != 1) {
            fprintf(stderr, "parsing " PROC_NET_DEV " failed unexpectedly\n");
            exit(EXIT_FAILURE);
        }

        /*
         * This works around a bug in the proc file where large interface names
         * or Rx byte counts eat the delimiter, breaking sscanf.
         */
        c = strchr(ifs->name, ':');
        if (c)
            *c = '\0';

        p = strchr(p, ':') + 1;

        ret = sscanf(p, "%u %u %u %u %*u %*u %*u %*u %u %u %u %u %*u %*u "
                     "%*u %*u\n", &ifs->rx_bytes, &ifs->rx_packets,
                     &ifs->rx_errors, &ifs->rx_dropped, &ifs->tx_bytes,
                     &ifs->tx_packets, &ifs->tx_errors, &ifs->tx_dropped);
        if (ret != 8) {
            fprintf(stderr, "parsing " PROC_NET_DEV " failed unexpectedly\n");
            exit(EXIT_FAILURE);
        }

        ifs->mtu = get_mtu(ifs->name);

        p = strchr(p, '\n') + 1;
        if (*p == '\0') {
            nr++;
            break;
        }

        ifs++;
    }

    ret = close(fd);
    if (ret) {
        perror("close");
        exit(EXIT_FAILURE);
    }

    return nr;
}

static void print_header(void)
{
    printf("               Rx                              Tx\n");
    printf("%-8s %-5s %-10s %-8s %-5s %-5s %-10s %-8s %-5s %-5s\n",
           "name", "MTU", "bytes", "packets", "errs", "drpd", "bytes",
           "packets", "errs", "drpd");
}

static int print_interfaces(struct if_stats *old, struct if_stats *new, int nr)
{
    int i = 0;

    while (nr--) {
        if (old->rx_packets || old->tx_packets) {
            printf("%-8s %-5u %-10u %-8u %-5u %-5u %-10u %-8u %-5u %-5u\n",
                   new->name, new->mtu,
                   new->rx_bytes - old->rx_bytes,
                   new->rx_packets - old->rx_packets,
                   new->rx_errors - old->rx_errors,
                   new->rx_dropped - old->rx_dropped,
                   new->tx_bytes - old->tx_bytes,
                   new->tx_packets - old->tx_packets,
                   new->tx_errors - old->tx_errors,
                   new->tx_dropped - old->tx_dropped);
            i++;
        }
        old++;
        new++;
    }

    return i;
}

static void usage(const char *cmd)
{
    fprintf(stderr, "usage: %s [ -r repeats] [ -d delay ]\n", cmd);
}

int iftop_main(int argc, char *argv[])
{
    struct if_stats ifs[2][MAX_IF];
    int count = 0, header_interval = 22, delay = 1, i;
    unsigned int toggle = 0;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-d")) {
            if (i >= argc - 1) {
                fprintf(stderr, "Option -d requires an argument.\n");
                exit(EXIT_FAILURE);
            }
            delay = atoi(argv[i++]);
            if (!delay)
                delay = 1;
            continue;
        }
        if (!strcmp(argv[i], "-r")) {
            if (i >= argc - 1) {
                fprintf(stderr, "Option -r requires an argument.\n");
                exit(EXIT_FAILURE);
            }
            header_interval = atoi(argv[i++]);
            if (header_interval < MAX_IF)
                header_interval = MAX_IF;
            continue;
        }
        if (!strcmp(argv[i], "-h")) {
            usage(argv[0]);
            exit(EXIT_SUCCESS);
        }
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    get_interfaces(ifs[!toggle]);
    if (header_interval)
        print_header();
    while (1) {
        int nr;

        sleep(delay);
        nr = get_interfaces(ifs[toggle]);
        if (header_interval && count + nr > header_interval) {
            print_header();
            count = 0;
        }
        count += print_interfaces(ifs[!toggle], ifs[toggle], nr);
        toggle = !toggle;
    }

    return 0;
}

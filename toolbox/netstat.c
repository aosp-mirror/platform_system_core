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

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>

typedef union iaddr iaddr;
typedef union iaddr6 iaddr6;

union iaddr {
    unsigned u;
    unsigned char b[4];
};

union iaddr6 {
    struct {
        unsigned a;
        unsigned b;
        unsigned c;
        unsigned d;
    } u;
    unsigned char b[16];
};

static const char *state2str(unsigned state)
{
    switch(state){
    case 0x1: return "ESTABLISHED";
    case 0x2: return "SYN_SENT";
    case 0x3: return "SYN_RECV";
    case 0x4: return "FIN_WAIT1";
    case 0x5: return "FIN_WAIT2";
    case 0x6: return "TIME_WAIT";
    case 0x7: return "CLOSE";
    case 0x8: return "CLOSE_WAIT";
    case 0x9: return "LAST_ACK";
    case 0xA: return "LISTEN";
    case 0xB: return "CLOSING";
    default: return "UNKNOWN";
    }
}

/* addr + : + port + \0 */
#define ADDR_LEN INET6_ADDRSTRLEN + 1 + 5 + 1

static void addr2str(int af, const void *addr, unsigned port, char *buf)
{
    if (inet_ntop(af, addr, buf, ADDR_LEN) == NULL) {
        *buf = '\0';
        return;
    }
    size_t len = strlen(buf);
    if (port) {
        snprintf(buf+len, ADDR_LEN-len, ":%d", port);
    } else {
        strncat(buf+len, ":*", ADDR_LEN-len-1);
    }
}

static void ipv4(const char *filename, const char *label) {
    FILE *fp = fopen(filename, "r");
    if (fp == NULL) {
        return;
    }
    char buf[BUFSIZ];
    fgets(buf, BUFSIZ, fp);
    while (fgets(buf, BUFSIZ, fp)){
        char lip[ADDR_LEN];
        char rip[ADDR_LEN];
        iaddr laddr, raddr;
        unsigned lport, rport, state, txq, rxq, num;
        int n = sscanf(buf, " %d: %x:%x %x:%x %x %x:%x",
                       &num, &laddr.u, &lport, &raddr.u, &rport,
                       &state, &txq, &rxq);
        if (n == 8) {
            addr2str(AF_INET, &laddr, lport, lip);
            addr2str(AF_INET, &raddr, rport, rip);

            printf("%4s  %6d %6d %-22s %-22s %s\n",
                   label, txq, rxq, lip, rip,
                   state2str(state));
        }
    }
    fclose(fp);
}

static void ipv6(const char *filename, const char *label) {
    FILE *fp = fopen(filename, "r");
    if (fp == NULL) {
        return;
    }
    char buf[BUFSIZ];
    fgets(buf, BUFSIZ, fp);
    while (fgets(buf, BUFSIZ, fp)){
        char lip[ADDR_LEN];
        char rip[ADDR_LEN];
        iaddr6 laddr6, raddr6;
        unsigned lport, rport, state, txq, rxq, num;
        int n = sscanf(buf, " %d: %8x%8x%8x%8x:%x %8x%8x%8x%8x:%x %x %x:%x",
                       &num, &laddr6.u.a, &laddr6.u.b, &laddr6.u.c, &laddr6.u.d, &lport,
                       &raddr6.u.a, &raddr6.u.b, &raddr6.u.c, &raddr6.u.d, &rport,
                       &state, &txq, &rxq);
        if (n == 14) {
            addr2str(AF_INET6, &laddr6, lport, lip);
            addr2str(AF_INET6, &raddr6, rport, rip);

            printf("%4s  %6d %6d %-22s %-22s %s\n",
                   label, txq, rxq, lip, rip,
                   state2str(state));
        }
    }
    fclose(fp);
}

int netstat_main(int argc, char *argv[])
{
    printf("Proto Recv-Q Send-Q Local Address          Foreign Address        State\n");
    ipv4("/proc/net/tcp",  "tcp");
    ipv4("/proc/net/udp",  "udp");
    ipv6("/proc/net/tcp6", "tcp6");
    ipv6("/proc/net/udp6", "udp6");
    return 0;
}

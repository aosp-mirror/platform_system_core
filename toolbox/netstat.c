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

#include <stdio.h>
#include <stdlib.h>

typedef union iaddr iaddr;

union iaddr {
    unsigned u;
    unsigned char b[4];
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

void addr2str(iaddr addr, unsigned port, char *buf)
{
    if(port) {
        snprintf(buf, 64, "%d.%d.%d.%d:%d",
                 addr.b[0], addr.b[1], addr.b[2], addr.b[3], port);
    } else {
        snprintf(buf, 64, "%d.%d.%d.%d:*",
                 addr.b[0], addr.b[1], addr.b[2], addr.b[3]);
    }
}

int netstat_main(int argc, char *argv[])
{
    char buf[512];
    char lip[64];
    char rip[64];
    iaddr laddr, raddr;
    unsigned lport, rport, state, txq, rxq, num;
    int n;
    FILE *fp;

    printf("Proto Recv-Q Send-Q Local Address          Foreign Address        State\n");

    fp = fopen("/proc/net/tcp", "r");
    if(fp != 0) {
        fgets(buf, 512, fp);
        while(fgets(buf, 512, fp)){
            n = sscanf(buf, " %d: %x:%x %x:%x %x %x:%x",
                       &num, &laddr.u, &lport, &raddr.u, &rport,
                       &state, &txq, &rxq);
            if(n == 8) {
                addr2str(laddr, lport, lip);
                addr2str(raddr, rport, rip);
                
                printf("tcp   %6d %6d %-22s %-22s %s\n", 
                       txq, rxq, lip, rip,
                       state2str(state));
            }
        }
        fclose(fp);
    }
    fp = fopen("/proc/net/udp", "r");
    if(fp != 0) {
        fgets(buf, 512, fp);
        while(fgets(buf, 512, fp)){
            n = sscanf(buf, " %d: %x:%x %x:%x %x %x:%x",
                       &num, &laddr.u, &lport, &raddr.u, &rport,
                       &state, &txq, &rxq);
            if(n == 8) {
                addr2str(laddr, lport, lip);
                addr2str(raddr, rport, rip);
                
                printf("udp   %6d %6d %-22s %-22s\n", 
                       txq, rxq, lip, rip);
            }
        }
        fclose(fp);
    }

    return 0;
}

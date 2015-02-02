/*
** Copyright 2006, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License"); 
** you may not use this file except in compliance with the License. 
** You may obtain a copy of the License at 
**
**     http://www.apache.org/licenses/LICENSE-2.0 
**
** Unless required by applicable law or agreed to in writing, software 
** distributed under the License is distributed on an "AS IS" BASIS, 
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
** See the License for the specific language governing permissions and 
** limitations under the License.
*/

#include <errno.h>
#include <dirent.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <netutils/dhcp.h>
#include <netutils/ifc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *ipaddr(in_addr_t addr)
{
    struct in_addr in_addr;

    in_addr.s_addr = addr;
    return inet_ntoa(in_addr);
}

static void usage(void)
{
    fprintf(stderr,"usage: netcfg [<interface> dhcp]\n");
    exit(1);
}

static int dump_interface(const char *name)
{
    unsigned addr, flags;
    unsigned char hwbuf[ETH_ALEN];
    int prefixLength;

    if(ifc_get_info(name, &addr, &prefixLength, &flags)) {
        return 0;
    }

    printf("%-8s %s  ", name, flags & 1 ? "UP  " : "DOWN");
    printf("%40s", ipaddr(addr));
    printf("/%-4d", prefixLength);
    printf("0x%08x ", flags);
    if (!ifc_get_hwaddr(name, hwbuf)) {
        int i;
        for(i=0; i < (ETH_ALEN-1); i++)
            printf("%02x:", hwbuf[i]);
        printf("%02x\n", hwbuf[i]);
    } else {
        printf("\n");
    }
    return 0;
}

static int dump_interfaces(void)
{
    DIR *d;
    struct dirent *de;

    d = opendir("/sys/class/net");
    if(d == 0) return -1;

    while((de = readdir(d))) {
        if(de->d_name[0] == '.') continue;
        dump_interface(de->d_name);
    }
    closedir(d);
    return 0;
}

int main(int argc, char **argv)
{
    if(ifc_init()) {
        perror("Cannot perform requested operation");
        exit(1);
    }

    if(argc == 1) {
        int result = dump_interfaces();
        ifc_close();
        return result;
    }

    if(argc != 3) usage();

    char* iname = argv[1];
    char* action = argv[2];
    if(strlen(iname) > 16) usage();

    if (!strcmp(action, "dhcp")) {
        if (do_dhcp(iname)) {
            fprintf(stderr, "dhcp failed: %s\n", strerror(errno));
            ifc_close();
            exit(1);
        }
    } else {
        fprintf(stderr,"no such action '%s'\n", action);
        usage();
    }

    ifc_close();
    return 0;
}

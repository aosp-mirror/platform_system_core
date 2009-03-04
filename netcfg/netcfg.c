/* system/bin/netcfg/netcfg.c
**
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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <dirent.h>

static int verbose = 0;

int ifc_init();
void ifc_close();
int ifc_up(char *iname);
int ifc_down(char *iname);
int ifc_remove_host_routes(char *iname);
int ifc_remove_default_route(char *iname);
int ifc_get_info(const char *name, unsigned *addr, unsigned *mask, unsigned *flags);
int do_dhcp(char *iname);

void die(const char *reason)
{
    perror(reason);
    exit(1);
}

const char *ipaddr(unsigned addr)
{
    static char buf[32];
    
    sprintf(buf,"%d.%d.%d.%d", 
            addr & 255,
            ((addr >> 8) & 255),
            ((addr >> 16) & 255), 
            (addr >> 24));
    return buf;
}

void usage(void)
{
    fprintf(stderr,"usage: netcfg [<interface> {dhcp|up|down}]\n");
    exit(1);    
}

int dump_interface(const char *name)
{
    unsigned addr, mask, flags;
    
    if(ifc_get_info(name, &addr, &mask, &flags)) {
        return 0;
    }

    printf("%-8s %s  ", name, flags & 1 ? "UP  " : "DOWN");
    printf("%-16s", ipaddr(addr));
    printf("%-16s", ipaddr(mask));
    printf("0x%08x\n", flags);
    return 0;
}

int dump_interfaces(void)
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

struct 
{
    const char *name;
    int nargs;
    void *func;
} CMDS[] = {
    { "dhcp",   1, do_dhcp },
    { "up",     1, ifc_up },
    { "down",   1, ifc_down },
    { "flhosts",  1, ifc_remove_host_routes },
    { "deldefault", 1, ifc_remove_default_route },
    { 0, 0, 0 },
};

static int call_func(void *_func, unsigned nargs, char **args)
{
    switch(nargs){
    case 1: {
        int (*func)(char *a0) = _func;
        return func(args[0]);
    }
    case 2: {
        int (*func)(char *a0, char *a1) = _func;
        return func(args[0], args[1]);
    }
    case 3: {
        int (*func)(char *a0, char *a1, char *a2) = _func;
        return func(args[0], args[1], args[2]);
    }
    default:
        return -1;
    }
}

int main(int argc, char **argv)
{
    char *iname;
    int n;
    
    if(ifc_init()) {
        die("Cannot perform requested operation");
    }

    if(argc == 1) {
        int result = dump_interfaces();
        ifc_close();
        return result;
    }

    if(argc < 3) usage();

    iname = argv[1];
    if(strlen(iname) > 16) usage();

    argc -= 2;
    argv += 2;
    while(argc > 0) {
        for(n = 0; CMDS[n].name; n++){
            if(!strcmp(argv[0], CMDS[n].name)) {
                char *cmdname = argv[0];
                int nargs = CMDS[n].nargs;
                
                argv[0] = iname;
                if(argc < nargs) {
                    fprintf(stderr, "not enough arguments for '%s'\n", cmdname);
                    ifc_close();
                    exit(1);
                }
                if(call_func(CMDS[n].func, nargs, argv)) {
                    fprintf(stderr, "action '%s' failed (%s)\n", cmdname, strerror(errno));
                    ifc_close();
                    exit(1);
                }
                argc -= nargs;
                argv += nargs;
                goto done;
            }
        }
        fprintf(stderr,"no such action '%s'\n", argv[0]);
        usage();
    done:
        ;
    }
    ifc_close();

    return 0;
}

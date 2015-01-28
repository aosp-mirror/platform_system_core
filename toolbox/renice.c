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
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sched.h>
#include <getopt.h>

static void
usage(const char *s)
{
    fprintf(stderr, "USAGE: %s [[-r] [-t TYPE] priority pids ...] [-g pid]\n", s);
    exit(EXIT_FAILURE);
}

void print_prio(pid_t pid)
{
    int sched;
    struct sched_param sp;

    printf("pid %d's priority: %d\n", pid, getpriority(PRIO_PROCESS, pid));

    printf("scheduling class: ");
    sched = sched_getscheduler(pid);
    switch (sched) {
    case SCHED_FIFO:
        printf("FIFO\n");
        break;
    case SCHED_RR:
        printf("RR\n");
        break;
    case SCHED_OTHER:
        printf("Normal\n");
        break;
    case -1:
        perror("sched_getscheduler");
        break;
    default:
        printf("Unknown\n");
    }

    sched_getparam(pid, &sp);
    printf("RT prio: %d (of %d to %d)\n", sp.sched_priority,
           sched_get_priority_min(sched), sched_get_priority_max(sched));
}

int get_sched(char *str)
{
    if (strcasecmp(str, "RR") == 0)
        return SCHED_RR;
    else if (strcasecmp(str, "FIFO") == 0)
        return SCHED_FIFO;
    else if (strcasecmp(str, "NORMAL") == 0)
        return SCHED_OTHER;
    else if (strcasecmp(str, "OTHER") == 0)
        return SCHED_OTHER;
    return SCHED_RR;
}

int renice_main(int argc, char *argv[])
{
    int prio;
    int realtime = 0;
    int opt;
    int sched = SCHED_RR;
    char *cmd = argv[0];

    do {
        opt = getopt(argc, argv, "rt:g:");
        if (opt == -1)
            break;
        switch (opt) {
        case 'r':
            // do realtime priority adjustment
            realtime = 1;
            break;
        case 't':
            sched = get_sched(optarg);
            break;
        case 'g':
            print_prio(atoi(optarg));
            return 0;
        default:
            usage(cmd);
        }
    } while (1);

    argc -= optind;
    argv += optind;

    if (argc < 1)
        usage(cmd);

    prio = atoi(argv[0]);
    argc--;
    argv++;

    if (argc < 1)
        usage(cmd);

    while(argc) {
        pid_t pid;

        pid = atoi(argv[0]);
        argc--;
        argv++;

        if (realtime) {
            struct sched_param sp = { .sched_priority = prio };
            int ret;

            ret = sched_setscheduler(pid, sched, &sp);
            if (ret) {
                perror("sched_set_scheduler");
                exit(EXIT_FAILURE);
            }
        } else {
            int ret;

            ret = setpriority(PRIO_PROCESS, pid, prio);
            if (ret) {
                perror("setpriority");
                exit(EXIT_FAILURE);
            }
        }
    }

    return 0;
}

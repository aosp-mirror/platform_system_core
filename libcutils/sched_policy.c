
/* libs/cutils/sched_policy.c
**
** Copyright 2007, The Android Open Source Project
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
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#ifdef HAVE_SCHED_H

#include <sched.h>

#include <cutils/sched_policy.h>

#ifndef SCHED_NORMAL
  #define SCHED_NORMAL 0
#endif

#ifndef SCHED_BATCH
  #define SCHED_BATCH 3
#endif

static int add_tid_to_cgroup(int tid, const char *grp_name)
{
    int fd;
    char path[255];
    char text[64];

    sprintf(path, "/dev/cpuctl/%s/tasks", grp_name);

    if ((fd = open(path, O_WRONLY)) < 0)
        return -1;

    sprintf(text, "%d", tid);
    if (write(fd, text, strlen(text)) < 0) {
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

int set_sched_policy(int tid, SchedPolicy policy)
{
    static int __sys_supports_schedgroups = -1;

    if (__sys_supports_schedgroups < 0) {
        if (!access("/dev/cpuctl/tasks", F_OK)) {
            __sys_supports_schedgroups = 1;
        } else {
            __sys_supports_schedgroups = 0;
        }
    }

    if (__sys_supports_schedgroups) {
        const char *grp = NULL;

        if (policy == SP_BACKGROUND) {
            grp = "bg_non_interactive";
        }

        if (add_tid_to_cgroup(tid, grp)) {
            if (errno != ESRCH && errno != ENOENT)
                return -errno;
        }
    } else {
        struct sched_param param;

        param.sched_priority = 0;
        sched_setscheduler(tid,
                           (policy == SP_BACKGROUND) ?
                            SCHED_BATCH : SCHED_NORMAL,
                           &param);
    }

    return 0;
}

#endif /* HAVE_SCHED_H */

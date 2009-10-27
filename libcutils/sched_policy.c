
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

static int __sys_supports_schedgroups = -1;

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

static inline void initialize()
{
    if (__sys_supports_schedgroups < 0) {
        if (!access("/dev/cpuctl/tasks", F_OK)) {
            __sys_supports_schedgroups = 1;
        } else {
            __sys_supports_schedgroups = 0;
        }
    }
}

/*
 * Try to get the scheduler group.
 *
 * The data from /proc/<pid>/cgroup looks like:
 *  2:cpu:/bg_non_interactive
 *
 * We return the part after the "/", which will be an empty string for
 * the default cgroup.  If the string is longer than "bufLen", the string
 * will be truncated.
 */
static int getSchedulerGroup(int tid, char* buf, size_t bufLen)
{
#ifdef HAVE_ANDROID_OS
    char pathBuf[32];
    char readBuf[256];
    ssize_t count;
    int fd;

    snprintf(pathBuf, sizeof(pathBuf), "/proc/%d/cgroup", tid);
    if ((fd = open(pathBuf, O_RDONLY)) < 0) {
        return -1;
    }

    count = read(fd, readBuf, sizeof(readBuf));
    if (count <= 0) {
        close(fd);
        errno = ENODATA;
        return -1;
    }
    close(fd);

    readBuf[--count] = '\0';    /* remove the '\n', now count==strlen */

    char* cp = strchr(readBuf, '/');
    if (cp == NULL) {
        readBuf[sizeof(readBuf)-1] = '\0';
        errno = ENODATA;
        return -1;
    }

    memcpy(buf, cp+1, count);   /* count-1 for cp+1, count+1 for NUL */
    return 0;
#else
    errno = ENOSYS;
    return -1;
#endif
}

int get_sched_policy(int tid, SchedPolicy *policy)
{
    initialize();

    if (__sys_supports_schedgroups) {
        char grpBuf[32];
        if (getSchedulerGroup(tid, grpBuf, sizeof(grpBuf)) < 0)
            return -1;
        if (grpBuf[0] == '\0') {
            *policy = SP_FOREGROUND;
        } else if (!strcmp(grpBuf, "bg_non_interactive")) {
            *policy = SP_BACKGROUND;
        } else {
            errno = ERANGE;
            return -1;
        }
    } else {
        int rc = sched_getscheduler(tid);
        if (rc < 0)
            return -1;
        else if (rc == SCHED_NORMAL)
            *policy = SP_FOREGROUND;
        else if (rc == SCHED_BATCH)
            *policy = SP_BACKGROUND;
        else {
            errno = ERANGE;
            return -1;
        }
    }
    return 0;
}

int set_sched_policy(int tid, SchedPolicy policy)
{
    initialize();

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

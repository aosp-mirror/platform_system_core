/* system/debuggerd/utility.c
**
** Copyright 2008, The Android Open Source Project
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

#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <log/logd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <assert.h>

#include "utility.h"

const int sleep_time_usec = 50000;         /* 0.05 seconds */
const int max_total_sleep_usec = 10000000; /* 10 seconds */

static int write_to_am(int fd, const char* buf, int len) {
    int to_write = len;
    while (to_write > 0) {
        int written = TEMP_FAILURE_RETRY( write(fd, buf + len - to_write, to_write) );
        if (written < 0) {
            /* hard failure */
            LOG("AM write failure (%d / %s)\n", errno, strerror(errno));
            return -1;
        }
        to_write -= written;
    }
    return len;
}

void _LOG(log_t* log, int scopeFlags, const char *fmt, ...) {
    char buf[512];
    bool want_tfd_write;
    bool want_log_write;
    bool want_amfd_write;
    int len = 0;

    va_list ap;
    va_start(ap, fmt);

    // where is the information going to go?
    want_tfd_write = log && log->tfd >= 0;
    want_log_write = IS_AT_FAULT(scopeFlags) && (!log || !log->quiet);
    want_amfd_write = IS_AT_FAULT(scopeFlags) && !IS_SENSITIVE(scopeFlags) && log && log->amfd >= 0;

    // if we're going to need the literal string, generate it once here
    if (want_tfd_write || want_amfd_write) {
        vsnprintf(buf, sizeof(buf), fmt, ap);
        len = strlen(buf);
    }

    if (want_tfd_write) {
        write(log->tfd, buf, len);
    }

    if (want_log_write) {
        // whatever goes to logcat also goes to the Activity Manager
        __android_log_vprint(ANDROID_LOG_INFO, "DEBUG", fmt, ap);
        if (want_amfd_write && len > 0) {
            int written = write_to_am(log->amfd, buf, len);
            if (written <= 0) {
                // timeout or other failure on write; stop informing the activity manager
                log->amfd = -1;
            }
        }
    }
    va_end(ap);
}

int wait_for_signal(pid_t tid, int* total_sleep_time_usec) {
    for (;;) {
        int status;
        pid_t n = waitpid(tid, &status, __WALL | WNOHANG);
        if (n < 0) {
            if(errno == EAGAIN) continue;
            LOG("waitpid failed: %s\n", strerror(errno));
            return -1;
        } else if (n > 0) {
            XLOG("waitpid: n=%d status=%08x\n", n, status);
            if (WIFSTOPPED(status)) {
                return WSTOPSIG(status);
            } else {
                LOG("unexpected waitpid response: n=%d, status=%08x\n", n, status);
                return -1;
            }
        }

        if (*total_sleep_time_usec > max_total_sleep_usec) {
            LOG("timed out waiting for tid=%d to die\n", tid);
            return -1;
        }

        /* not ready yet */
        XLOG("not ready yet\n");
        usleep(sleep_time_usec);
        *total_sleep_time_usec += sleep_time_usec;
    }
}

void wait_for_stop(pid_t tid, int* total_sleep_time_usec) {
    siginfo_t si;
    while (TEMP_FAILURE_RETRY(ptrace(PTRACE_GETSIGINFO, tid, 0, &si)) < 0 && errno == ESRCH) {
        if (*total_sleep_time_usec > max_total_sleep_usec) {
            LOG("timed out waiting for tid=%d to stop\n", tid);
            break;
        }

        usleep(sleep_time_usec);
        *total_sleep_time_usec += sleep_time_usec;
    }
}

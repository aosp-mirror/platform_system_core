/*
 * Copyright 2008, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stddef.h>
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

const int sleep_time_usec = 50000;         // 0.05 seconds
const int max_total_sleep_usec = 10000000; // 10 seconds

static int write_to_am(int fd, const char* buf, int len) {
  int to_write = len;
  while (to_write > 0) {
    int written = TEMP_FAILURE_RETRY( write(fd, buf + len - to_write, to_write) );
    if (written < 0) {
      // hard failure
      LOG("AM write failure (%d / %s)\n", errno, strerror(errno));
      return -1;
    }
    to_write -= written;
  }
  return len;
}

void _LOG(log_t* log, int scopeFlags, const char* fmt, ...) {
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
      if (errno == EAGAIN)
        continue;
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

    // not ready yet
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

#if defined (__mips__)
#define DUMP_MEMORY_AS_ASCII 1
#else
#define DUMP_MEMORY_AS_ASCII 0
#endif

void dump_memory(log_t* log, pid_t tid, uintptr_t addr, int scope_flags) {
    char code_buffer[64];
    char ascii_buffer[32];
    uintptr_t p, end;

    p = addr & ~(sizeof(long) - 1);
    /* Dump 32 bytes before addr */
    p -= 32;
    if (p > addr) {
        /* catch underflow */
        p = 0;
    }
    /* Dump 256 bytes */
    end = p + 256;
    /* catch overflow; 'end - p' has to be multiples of 16 */
    while (end < p) {
        end -= 16;
    }

    /* Dump the code around PC as:
     *  addr             contents                           ascii
     *  0000000000008d34 ef000000e8bd0090 e1b00000512fff1e  ............../Q
     *  0000000000008d44 ea00b1f9e92d0090 e3a070fcef000000  ......-..p......
     * On 32-bit machines, there are still 16 bytes per line but addresses and
     * words are of course presented differently.
     */
    while (p < end) {
        char* asc_out = ascii_buffer;

        int len = snprintf(code_buffer, sizeof(code_buffer), "%" PRIPTR " ", p);

        for (size_t i = 0; i < 16/sizeof(long); i++) {
            long data = ptrace(PTRACE_PEEKTEXT, tid, (void*)p, NULL);
            if (data == -1 && errno != 0) {
                // ptrace failed, probably because we're dumping memory in an
                // unmapped or inaccessible page.
#ifdef __LP64__
                len += sprintf(code_buffer + len, "---------------- ");
#else
                len += sprintf(code_buffer + len, "-------- ");
#endif
            } else {
                len += sprintf(code_buffer + len, "%" PRIPTR " ",
                               static_cast<uintptr_t>(data));
            }

#if DUMP_MEMORY_AS_ASCII
            for (size_t j = 0; j < sizeof(long); j++) {
                /*
                 * Our isprint() allows high-ASCII characters that display
                 * differently (often badly) in different viewers, so we
                 * just use a simpler test.
                 */
                char val = (data >> (j*8)) & 0xff;
                if (val >= 0x20 && val < 0x7f) {
                    *asc_out++ = val;
                } else {
                    *asc_out++ = '.';
                }
            }
#endif
            p += sizeof(long);
        }
        *asc_out = '\0';
        _LOG(log, scope_flags, "    %s %s\n", code_buffer, ascii_buffer);
    }
}

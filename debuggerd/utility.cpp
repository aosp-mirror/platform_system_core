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

#define LOG_TAG "DEBUG"

#include "utility.h"

#include <errno.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#include <backtrace/Backtrace.h>
#include <log/log.h>

const int SLEEP_TIME_USEC = 50000;         // 0.05 seconds
const int MAX_TOTAL_SLEEP_USEC = 10000000; // 10 seconds

static int write_to_am(int fd, const char* buf, int len) {
  int to_write = len;
  while (to_write > 0) {
    int written = TEMP_FAILURE_RETRY(write(fd, buf + len - to_write, to_write));
    if (written < 0) {
      // hard failure
      ALOGE("AM write failure (%d / %s)\n", errno, strerror(errno));
      return -1;
    }
    to_write -= written;
  }
  return len;
}

// Whitelist output desired in the logcat output.
bool is_allowed_in_logcat(enum logtype ltype) {
  if ((ltype == ERROR)
   || (ltype == HEADER)
   || (ltype == REGISTERS)
   || (ltype == BACKTRACE)) {
    return true;
  }
  return false;
}

void _LOG(log_t* log, enum logtype ltype, const char* fmt, ...) {
  bool write_to_tombstone = (log->tfd != -1);
  bool write_to_logcat = is_allowed_in_logcat(ltype)
                      && log->crashed_tid != -1
                      && log->current_tid != -1
                      && (log->crashed_tid == log->current_tid);
  bool write_to_activitymanager = (log->amfd != -1);

  char buf[512];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);

  size_t len = strlen(buf);
  if (len <= 0) {
    return;
  }

  if (write_to_tombstone) {
    TEMP_FAILURE_RETRY(write(log->tfd, buf, len));
  }

  if (write_to_logcat) {
    __android_log_buf_write(LOG_ID_CRASH, ANDROID_LOG_INFO, LOG_TAG, buf);
    if (write_to_activitymanager) {
      int written = write_to_am(log->amfd, buf, len);
      if (written <= 0) {
        // timeout or other failure on write; stop informing the activity manager
        log->amfd = -1;
      }
    }
  }
}

int wait_for_sigstop(pid_t tid, int* total_sleep_time_usec, bool* detach_failed) {
  bool allow_dead_tid = false;
  for (;;) {
    int status;
    pid_t n = TEMP_FAILURE_RETRY(waitpid(tid, &status, __WALL | WNOHANG));
    if (n == -1) {
      ALOGE("waitpid failed: tid %d, %s", tid, strerror(errno));
      break;
    } else if (n == tid) {
      if (WIFSTOPPED(status)) {
        return WSTOPSIG(status);
      } else {
        ALOGE("unexpected waitpid response: n=%d, status=%08x\n", n, status);
        // This is the only circumstance under which we can allow a detach
        // to fail with ESRCH, which indicates the tid has exited.
        allow_dead_tid = true;
        break;
      }
    }

    if (*total_sleep_time_usec > MAX_TOTAL_SLEEP_USEC) {
      ALOGE("timed out waiting for stop signal: tid=%d", tid);
      break;
    }

    usleep(SLEEP_TIME_USEC);
    *total_sleep_time_usec += SLEEP_TIME_USEC;
  }

  if (ptrace(PTRACE_DETACH, tid, 0, 0) != 0) {
    if (allow_dead_tid && errno == ESRCH) {
      ALOGE("tid exited before attach completed: tid %d", tid);
    } else {
      *detach_failed = true;
      ALOGE("detach failed: tid %d, %s", tid, strerror(errno));
    }
  }
  return -1;
}

#if defined (__mips__)
#define DUMP_MEMORY_AS_ASCII 1
#else
#define DUMP_MEMORY_AS_ASCII 0
#endif

void dump_memory(log_t* log, pid_t tid, uintptr_t addr) {
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
        _LOG(log, logtype::MEMORY, "    %s %s\n", code_buffer, ascii_buffer);
    }
}

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

#include "libdebuggerd/utility.h"

#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#include <string>

#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <backtrace/Backtrace.h>
#include <log/log.h>

using android::base::unique_fd;

// Whitelist output desired in the logcat output.
bool is_allowed_in_logcat(enum logtype ltype) {
  if ((ltype == HEADER)
   || (ltype == REGISTERS)
   || (ltype == BACKTRACE)) {
    return true;
  }
  return false;
}

static bool should_write_to_kmsg() {
  // Write to kmsg if tombstoned isn't up, and we're able to do so.
  if (!android::base::GetBoolProperty("ro.debuggable", false)) {
    return false;
  }

  if (android::base::GetProperty("init.svc.tombstoned", "") == "running") {
    return false;
  }

  return true;
}

__attribute__((__weak__, visibility("default")))
void _LOG(log_t* log, enum logtype ltype, const char* fmt, ...) {
  bool write_to_tombstone = (log->tfd != -1);
  bool write_to_logcat = is_allowed_in_logcat(ltype)
                      && log->crashed_tid != -1
                      && log->current_tid != -1
                      && (log->crashed_tid == log->current_tid);
  static bool write_to_kmsg = should_write_to_kmsg();

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
    __android_log_buf_write(LOG_ID_CRASH, ANDROID_LOG_FATAL, LOG_TAG, buf);
    if (log->amfd_data != nullptr) {
      *log->amfd_data += buf;
    }

    if (write_to_kmsg) {
      unique_fd kmsg_fd(open("/dev/kmsg_debug", O_WRONLY | O_APPEND | O_CLOEXEC));
      if (kmsg_fd.get() >= 0) {
        // Our output might contain newlines which would otherwise be handled by the android logger.
        // Split the lines up ourselves before sending to the kernel logger.
        if (buf[len - 1] == '\n') {
          buf[len - 1] = '\0';
        }

        std::vector<std::string> fragments = android::base::Split(buf, "\n");
        for (const std::string& fragment : fragments) {
          static constexpr char prefix[] = "<3>DEBUG: ";
          struct iovec iov[3];
          iov[0].iov_base = const_cast<char*>(prefix);
          iov[0].iov_len = strlen(prefix);
          iov[1].iov_base = const_cast<char*>(fragment.c_str());
          iov[1].iov_len = fragment.length();
          iov[2].iov_base = const_cast<char*>("\n");
          iov[2].iov_len = 1;
          TEMP_FAILURE_RETRY(writev(kmsg_fd.get(), iov, 3));
        }
      }
    }
  }
}

bool wait_for_signal(pid_t tid, siginfo_t* siginfo) {
  while (true) {
    int status;
    pid_t n = TEMP_FAILURE_RETRY(waitpid(tid, &status, __WALL));
    if (n == -1) {
      ALOGE("waitpid failed: tid %d, %s", tid, strerror(errno));
      return false;
    } else if (n == tid) {
      if (WIFSTOPPED(status)) {
        if (ptrace(PTRACE_GETSIGINFO, tid, nullptr, siginfo) != 0) {
          ALOGE("PTRACE_GETSIGINFO failed: %s", strerror(errno));
          return false;
        }
        return true;
      } else {
        ALOGE("unexpected waitpid response: n=%d, status=%08x\n", n, status);
        // This is the only circumstance under which we can allow a detach
        // to fail with ESRCH, which indicates the tid has exited.
        return false;
      }
    }
  }
}

#define MEMORY_BYTES_TO_DUMP 256
#define MEMORY_BYTES_PER_LINE 16

void dump_memory(log_t* log, Backtrace* backtrace, uintptr_t addr, const char* fmt, ...) {
  std::string log_msg;
  va_list ap;
  va_start(ap, fmt);
  android::base::StringAppendV(&log_msg, fmt, ap);
  va_end(ap);

  // Align the address to sizeof(long) and start 32 bytes before the address.
  addr &= ~(sizeof(long) - 1);
  if (addr >= 4128) {
    addr -= 32;
  }

  // Don't bother if the address looks too low, or looks too high.
  if (addr < 4096 ||
#if defined(__LP64__)
      addr > 0x4000000000000000UL - MEMORY_BYTES_TO_DUMP) {
#else
      addr > 0xffff0000 - MEMORY_BYTES_TO_DUMP) {
#endif
    return;
  }

  _LOG(log, logtype::MEMORY, "\n%s\n", log_msg.c_str());

  // Dump 256 bytes
  uintptr_t data[MEMORY_BYTES_TO_DUMP/sizeof(uintptr_t)];
  memset(data, 0, MEMORY_BYTES_TO_DUMP);
  size_t bytes = backtrace->Read(addr, reinterpret_cast<uint8_t*>(data), sizeof(data));
  if (bytes % sizeof(uintptr_t) != 0) {
    // This should never happen, but just in case.
    ALOGE("Bytes read %zu, is not a multiple of %zu", bytes, sizeof(uintptr_t));
    bytes &= ~(sizeof(uintptr_t) - 1);
  }

  uintptr_t start = 0;
  bool skip_2nd_read = false;
  if (bytes == 0) {
    // In this case, we might want to try another read at the beginning of
    // the next page only if it's within the amount of memory we would have
    // read.
    size_t page_size = sysconf(_SC_PAGE_SIZE);
    start = ((addr + (page_size - 1)) & ~(page_size - 1)) - addr;
    if (start == 0 || start >= MEMORY_BYTES_TO_DUMP) {
      skip_2nd_read = true;
    }
  }

  if (bytes < MEMORY_BYTES_TO_DUMP && !skip_2nd_read) {
    // Try to do one more read. This could happen if a read crosses a map,
    // but the maps do not have any break between them. Or it could happen
    // if reading from an unreadable map, but the read would cross back
    // into a readable map. Only requires one extra read because a map has
    // to contain at least one page, and the total number of bytes to dump
    // is smaller than a page.
    size_t bytes2 = backtrace->Read(addr + start + bytes, reinterpret_cast<uint8_t*>(data) + bytes,
                                    sizeof(data) - bytes - start);
    bytes += bytes2;
    if (bytes2 > 0 && bytes % sizeof(uintptr_t) != 0) {
      // This should never happen, but we'll try and continue any way.
      ALOGE("Bytes after second read %zu, is not a multiple of %zu", bytes, sizeof(uintptr_t));
      bytes &= ~(sizeof(uintptr_t) - 1);
    }
  }

  // Dump the code around memory as:
  //  addr             contents                           ascii
  //  0000000000008d34 ef000000e8bd0090 e1b00000512fff1e  ............../Q
  //  0000000000008d44 ea00b1f9e92d0090 e3a070fcef000000  ......-..p......
  // On 32-bit machines, there are still 16 bytes per line but addresses and
  // words are of course presented differently.
  uintptr_t* data_ptr = data;
  size_t current = 0;
  size_t total_bytes = start + bytes;
  for (size_t line = 0; line < MEMORY_BYTES_TO_DUMP / MEMORY_BYTES_PER_LINE; line++) {
    std::string logline;
    android::base::StringAppendF(&logline, "    %" PRIPTR, addr);

    addr += MEMORY_BYTES_PER_LINE;
    std::string ascii;
    for (size_t i = 0; i < MEMORY_BYTES_PER_LINE / sizeof(uintptr_t); i++) {
      if (current >= start && current + sizeof(uintptr_t) <= total_bytes) {
        android::base::StringAppendF(&logline, " %" PRIPTR, *data_ptr);

        // Fill out the ascii string from the data.
        uint8_t* ptr = reinterpret_cast<uint8_t*>(data_ptr);
        for (size_t val = 0; val < sizeof(uintptr_t); val++, ptr++) {
          if (*ptr >= 0x20 && *ptr < 0x7f) {
            ascii += *ptr;
          } else {
            ascii += '.';
          }
        }
        data_ptr++;
      } else {
        logline += ' ' + std::string(sizeof(uintptr_t) * 2, '-');
        ascii += std::string(sizeof(uintptr_t), '.');
      }
      current += sizeof(uintptr_t);
    }
    _LOG(log, logtype::MEMORY, "%s  %s\n", logline.c_str(), ascii.c_str());
  }
}

void read_with_default(const char* path, char* buf, size_t len, const char* default_value) {
  unique_fd fd(open(path, O_RDONLY | O_CLOEXEC));
  if (fd != -1) {
    int rc = TEMP_FAILURE_RETRY(read(fd.get(), buf, len - 1));
    if (rc != -1) {
      buf[rc] = '\0';

      // Trim trailing newlines.
      if (rc > 0 && buf[rc - 1] == '\n') {
        buf[rc - 1] = '\0';
      }
      return;
    }
  }
  strcpy(buf, default_value);
}

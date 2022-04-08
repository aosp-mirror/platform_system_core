/* system/debuggerd/utility.h
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

#ifndef _DEBUGGERD_UTILITY_H
#define _DEBUGGERD_UTILITY_H

#include <inttypes.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <sys/types.h>

#include <string>

#include <android-base/macros.h>

struct log_t {
  // Tombstone file descriptor.
  int tfd;
  // Data to be sent to the Activity Manager.
  std::string* amfd_data;
  // The tid of the thread that crashed.
  pid_t crashed_tid;
  // The tid of the thread we are currently working with.
  pid_t current_tid;
  // logd daemon crash, can block asking for logcat data, allow suppression.
  bool should_retrieve_logcat;

  log_t()
      : tfd(-1),
        amfd_data(nullptr),
        crashed_tid(-1),
        current_tid(-1),
        should_retrieve_logcat(true) {}
};

// List of types of logs to simplify the logging decision in _LOG
enum logtype {
  HEADER,
  THREAD,
  REGISTERS,
  FP_REGISTERS,
  BACKTRACE,
  MAPS,
  MEMORY,
  STACK,
  LOGS,
  OPEN_FILES
};

#if defined(__LP64__)
#define PRIPTR "016" PRIx64
typedef uint64_t word_t;
#else
#define PRIPTR "08" PRIx64
typedef uint32_t word_t;
#endif

// Log information onto the tombstone.
void _LOG(log_t* log, logtype ltype, const char* fmt, ...) __attribute__((format(printf, 3, 4)));
void _VLOG(log_t* log, logtype ltype, const char* fmt, va_list ap);

namespace unwindstack {
class Unwinder;
class Memory;
}

void log_backtrace(log_t* log, unwindstack::Unwinder* unwinder, const char* prefix);

void dump_memory(log_t* log, unwindstack::Memory* backtrace, uint64_t addr, const std::string&);

void read_with_default(const char* path, char* buf, size_t len, const char* default_value);

void drop_capabilities();

bool signal_has_sender(const siginfo_t*, pid_t caller_pid);
bool signal_has_si_addr(const siginfo_t*);
void get_signal_sender(char* buf, size_t n, const siginfo_t*);
const char* get_signame(const siginfo_t*);
const char* get_sigcode(const siginfo_t*);

#endif // _DEBUGGERD_UTILITY_H

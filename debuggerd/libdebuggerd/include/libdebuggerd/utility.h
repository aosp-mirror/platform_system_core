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

#include <signal.h>
#include <stdbool.h>
#include <sys/types.h>

#include <string>

#include <android-base/macros.h>
#include <backtrace/Backtrace.h>

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

// Log information onto the tombstone.
void _LOG(log_t* log, logtype ltype, const char* fmt, ...) __attribute__((format(printf, 3, 4)));

namespace unwindstack {
class Memory;
}

void dump_memory(log_t* log, unwindstack::Memory* backtrace, uint64_t addr, const char* fmt, ...);

void read_with_default(const char* path, char* buf, size_t len, const char* default_value);

void drop_capabilities();

bool signal_has_si_addr(int si_signo, int si_code);
const char* get_signame(int sig);
const char* get_sigcode(int signo, int code);

#endif // _DEBUGGERD_UTILITY_H

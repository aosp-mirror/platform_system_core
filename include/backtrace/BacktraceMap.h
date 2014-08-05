/*
 * Copyright (C) 2014 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _BACKTRACE_BACKTRACE_MAP_H
#define _BACKTRACE_BACKTRACE_MAP_H

#include <stdint.h>
#include <sys/types.h>
#ifdef USE_MINGW
// MINGW does not define these constants.
#define PROT_NONE 0
#define PROT_READ 0x1
#define PROT_WRITE 0x2
#define PROT_EXEC 0x4
#else
#include <sys/mman.h>
#endif

#include <deque>
#include <string>

struct backtrace_map_t {
  uintptr_t start;
  uintptr_t end;
  int flags;
  std::string name;
};

class BacktraceMap {
public:
  // If uncached is true, then parse the current process map as of the call.
  // Passing a map created with uncached set to true to Backtrace::Create()
  // is unsupported.
  static BacktraceMap* Create(pid_t pid, bool uncached = false);

  virtual ~BacktraceMap();

  // Get the map data structure for the given address.
  virtual const backtrace_map_t* Find(uintptr_t addr);

  // The flags returned are the same flags as used by the mmap call.
  // The values are PROT_*.
  int GetFlags(uintptr_t pc) {
    const backtrace_map_t* map = Find(pc);
    if (map) {
      return map->flags;
    }
    return PROT_NONE;
  }

  bool IsReadable(uintptr_t pc) { return GetFlags(pc) & PROT_READ; }
  bool IsWritable(uintptr_t pc) { return GetFlags(pc) & PROT_WRITE; }
  bool IsExecutable(uintptr_t pc) { return GetFlags(pc) & PROT_EXEC; }

  typedef std::deque<backtrace_map_t>::iterator iterator;
  iterator begin() { return maps_.begin(); }
  iterator end() { return maps_.end(); }

  typedef std::deque<backtrace_map_t>::const_iterator const_iterator;
  const_iterator begin() const { return maps_.begin(); }
  const_iterator end() const { return maps_.end(); }

  virtual bool Build();

protected:
  BacktraceMap(pid_t pid);

  virtual bool ParseLine(const char* line, backtrace_map_t* map);

  std::deque<backtrace_map_t> maps_;
  pid_t pid_;
};

#endif // _BACKTRACE_BACKTRACE_MAP_H

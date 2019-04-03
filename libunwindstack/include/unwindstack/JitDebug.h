/*
 * Copyright (C) 2017 The Android Open Source Project
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

#ifndef _LIBUNWINDSTACK_JIT_DEBUG_H
#define _LIBUNWINDSTACK_JIT_DEBUG_H

#include <stdint.h>

#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <unwindstack/Global.h>
#include <unwindstack/Memory.h>

namespace unwindstack {

// Forward declarations.
class Maps;
enum ArchEnum : uint8_t;

template <typename Symfile>
class JitDebug {
 public:
  static std::unique_ptr<JitDebug> Create(ArchEnum arch, std::shared_ptr<Memory>& memory,
                                          std::vector<std::string> search_libs = {});
  virtual ~JitDebug() {}

  // Find symbol file for given pc.
  virtual Symfile* Get(Maps* maps, uint64_t pc) = 0;

  // Find symbol for given pc.
  bool GetFunctionName(Maps* maps, uint64_t pc, std::string* name, uint64_t* offset) {
    Symfile* file = Get(maps, pc);
    return file != nullptr && file->GetFunctionName(pc, name, offset);
  }
};

}  // namespace unwindstack

#endif  // _LIBUNWINDSTACK_JIT_DEBUG_H

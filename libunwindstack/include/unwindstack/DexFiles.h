/*
 * Copyright (C) 2018 The Android Open Source Project
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

#ifndef _LIBUNWINDSTACK_DEX_FILES_H
#define _LIBUNWINDSTACK_DEX_FILES_H

#include <stdint.h>

#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

namespace unwindstack {

// Forward declarations.
class DexFile;
class Maps;
struct MapInfo;
class Memory;
enum ArchEnum : uint8_t;

class DexFiles {
 public:
  explicit DexFiles(std::shared_ptr<Memory>& memory);
  ~DexFiles();

  DexFile* GetDexFile(uint64_t dex_offset, MapInfo* info);

  void GetMethodInformation(uint64_t dex_offset, MapInfo* info, std::string* method_name,
                            uint64_t* method_offset);

  void SetArch(ArchEnum arch);

 private:
  std::shared_ptr<Memory> memory_;
  std::mutex files_lock_;
  std::unordered_map<uint64_t, DexFile*> files_;
};

}  // namespace unwindstack

#endif  // _LIBUNWINDSTACK_DEX_FILES_H

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

#include <stdint.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <memory>

#include <unwindstack/DexFiles.h>
#include <unwindstack/MapInfo.h>
#include <unwindstack/Memory.h>

#include "DexFile.h"

namespace unwindstack {

DexFiles::DexFiles(std::shared_ptr<Memory>& memory) : memory_(memory) {}

DexFiles::~DexFiles() {
  for (auto& entry : files_) {
    delete entry.second;
  }
}

DexFile* DexFiles::GetDexFile(uint64_t dex_file_offset, MapInfo* info) {
  // Lock while processing the data.
  std::lock_guard<std::mutex> guard(files_lock_);
  DexFile* dex_file;
  auto entry = files_.find(dex_file_offset);
  if (entry == files_.end()) {
    dex_file = DexFile::Create(dex_file_offset, memory_.get(), info);
    files_[dex_file_offset] = dex_file;
  } else {
    dex_file = entry->second;
  }
  return dex_file;
}

void DexFiles::GetMethodInformation(uint64_t dex_offset, MapInfo* info, std::string* method_name,
                                    uint64_t* method_offset) {
  DexFile* dex_file = GetDexFile(dex_offset, info);
  if (dex_file != nullptr) {
    dex_file->GetMethodInformation(dex_offset, method_name, method_offset);
  }
}

void DexFiles::SetArch(ArchEnum) {}

}  // namespace unwindstack

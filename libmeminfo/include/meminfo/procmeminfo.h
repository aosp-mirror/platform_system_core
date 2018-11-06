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

#pragma once

#include <sys/types.h>

#include <string>
#include <vector>

#include "meminfo.h"

namespace android {
namespace meminfo {

class ProcMemInfo final {
    // Per-process memory accounting
  public:
    ProcMemInfo(pid_t pid, bool get_wss = false);

    const std::vector<Vma>& Maps();
    const MemUsage& Usage();
    const MemUsage& Wss();

    bool WssReset();
    ~ProcMemInfo() = default;

  private:
    bool ReadMaps(bool get_wss);
    bool ReadVmaStats(int pagemap_fd, Vma& vma, bool get_wss);

    pid_t pid_;
    bool get_wss_;

    std::vector<Vma> maps_;

    MemUsage usage_;
    MemUsage wss_;
};

}  // namespace meminfo
}  // namespace android

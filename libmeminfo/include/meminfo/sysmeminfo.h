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

#include <map>
#include <string>
#include <vector>

namespace android {
namespace meminfo {

class SysMemInfo final {
    // System or Global memory accounting
  public:
    static const std::vector<std::string> kDefaultSysMemInfoTags;

    SysMemInfo() = default;

    // Parse /proc/meminfo and read values that are needed
    bool ReadMemInfo(const std::string& path = "/proc/meminfo");
    bool ReadMemInfo(const std::vector<std::string>& tags,
                     const std::string& path = "/proc/meminfo");

    // getters
    uint64_t mem_total_kb() { return mem_in_kb_["MemTotal:"]; }
    uint64_t mem_free_kb() { return mem_in_kb_["MemFree:"]; }
    uint64_t mem_buffers_kb() { return mem_in_kb_["Buffers:"]; }
    uint64_t mem_cached_kb() { return mem_in_kb_["Cached:"]; }
    uint64_t mem_shmem_kb() { return mem_in_kb_["Shmem:"]; }
    uint64_t mem_slab_kb() { return mem_in_kb_["Slab:"]; }
    uint64_t mem_slab_reclailmable_kb() { return mem_in_kb_["SReclaimable:"]; }
    uint64_t mem_slab_unreclaimable_kb() { return mem_in_kb_["SUnreclaim:"]; }
    uint64_t mem_swap_kb() { return mem_in_kb_["SwapTotal:"]; }
    uint64_t mem_free_swap_kb() { return mem_in_kb_["SwapFree:"]; }
    uint64_t mem_zram_kb() { return mem_in_kb_["Zram:"]; }
    uint64_t mem_mapped_kb() { return mem_in_kb_["Mapped:"]; }
    uint64_t mem_vmalloc_used_kb() { return mem_in_kb_["VmallocUsed:"]; }
    uint64_t mem_page_tables_kb() { return mem_in_kb_["PageTables:"]; }
    uint64_t mem_kernel_stack_kb() { return mem_in_kb_["KernelStack:"]; }

  private:
    std::map<std::string, uint64_t> mem_in_kb_;
};

}  // namespace meminfo
}  // namespace android

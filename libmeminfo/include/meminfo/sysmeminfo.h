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

#include <functional>
#include <map>
#include <string>
#include <vector>

namespace android {
namespace meminfo {

class SysMemInfo final {
    // System or Global memory accounting
  public:
    static constexpr const char* kMemTotal = "MemTotal:";
    static constexpr const char* kMemFree = "MemFree:";
    static constexpr const char* kMemBuffers = "Buffers:";
    static constexpr const char* kMemCached = "Cached:";
    static constexpr const char* kMemShmem = "Shmem:";
    static constexpr const char* kMemSlab = "Slab:";
    static constexpr const char* kMemSReclaim = "SReclaimable:";
    static constexpr const char* kMemSUnreclaim = "SUnreclaim:";
    static constexpr const char* kMemSwapTotal = "SwapTotal:";
    static constexpr const char* kMemSwapFree = "SwapFree:";
    static constexpr const char* kMemMapped = "Mapped:";
    static constexpr const char* kMemVmallocUsed = "VmallocUsed:";
    static constexpr const char* kMemPageTables = "PageTables:";
    static constexpr const char* kMemKernelStack = "KernelStack:";

    static const std::vector<std::string> kDefaultSysMemInfoTags;

    SysMemInfo() = default;

    // Parse /proc/meminfo and read values that are needed
    bool ReadMemInfo(const std::string& path = "/proc/meminfo");
    bool ReadMemInfo(const std::vector<std::string>& tags, std::vector<uint64_t>* out,
                     const std::string& path = "/proc/meminfo");
    bool ReadMemInfo(std::vector<uint64_t>* out, const std::string& path = "/proc/meminfo");

    // Parse /proc/vmallocinfo and return total physical memory mapped
    // in vmalloc area by the kernel.
    // Note that this deliberately ignores binder buffers. They are _always_
    // mapped in a process and are counted for in each process.
    uint64_t ReadVmallocInfo();

    // getters
    uint64_t mem_total_kb() { return mem_in_kb_[kMemTotal]; }
    uint64_t mem_free_kb() { return mem_in_kb_[kMemFree]; }
    uint64_t mem_buffers_kb() { return mem_in_kb_[kMemBuffers]; }
    uint64_t mem_cached_kb() { return mem_in_kb_[kMemCached]; }
    uint64_t mem_shmem_kb() { return mem_in_kb_[kMemShmem]; }
    uint64_t mem_slab_kb() { return mem_in_kb_[kMemSlab]; }
    uint64_t mem_slab_reclaimable_kb() { return mem_in_kb_[kMemSReclaim]; }
    uint64_t mem_slab_unreclaimable_kb() { return mem_in_kb_[kMemSUnreclaim]; }
    uint64_t mem_swap_kb() { return mem_in_kb_[kMemSwapTotal]; }
    uint64_t mem_swap_free_kb() { return mem_in_kb_[kMemSwapFree]; }
    uint64_t mem_mapped_kb() { return mem_in_kb_[kMemMapped]; }
    uint64_t mem_vmalloc_used_kb() { return mem_in_kb_[kMemVmallocUsed]; }
    uint64_t mem_page_tables_kb() { return mem_in_kb_[kMemPageTables]; }
    uint64_t mem_kernel_stack_kb() { return mem_in_kb_[kMemKernelStack]; }
    uint64_t mem_zram_kb(const std::string& zram_dev = "");

  private:
    std::map<std::string, uint64_t> mem_in_kb_;
    bool MemZramDevice(const std::string& zram_dev, uint64_t* mem_zram_dev);
    bool ReadMemInfo(const std::vector<std::string>& tags, const std::string& path,
                     std::function<void(const std::string&, uint64_t)> store_val);
};

// Parse /proc/vmallocinfo and return total physical memory mapped
// in vmalloc area by the kernel. Note that this deliberately ignores binder buffers. They are
// _always_ mapped in a process and are counted for in each process.
uint64_t ReadVmallocInfo(const std::string& path = "/proc/vmallocinfo");

}  // namespace meminfo
}  // namespace android

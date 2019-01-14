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

using VmaCallback = std::function<void(const Vma&)>;

class ProcMemInfo final {
    // Per-process memory accounting
  public:
    // Reset the working set accounting of the process via /proc/<pid>/clear_refs
    static bool ResetWorkingSet(pid_t pid);

    ProcMemInfo(pid_t pid, bool get_wss = false, uint64_t pgflags = 0, uint64_t pgflags_mask = 0);

    const std::vector<Vma>& Maps();
    const MemUsage& Usage();
    const MemUsage& Wss();

    // Collect all 'vma' or 'maps' from /proc/<pid>/smaps and store them in 'maps_'. Returns a
    // constant reference to the vma vector after the collection is done.
    //
    // Each 'struct Vma' is *fully* populated by this method (unlike SmapsOrRollup).
    const std::vector<Vma>& Smaps(const std::string& path = "");

    // This method reads /proc/<pid>/smaps and calls the callback() for each
    // vma or map that it finds. The map is converted to 'struct Vma' object which is then
    // passed to the callback.
    // Returns 'false' if the file is malformed.
    bool ForEachVma(const VmaCallback& callback);

    // Used to parse either of /proc/<pid>/{smaps, smaps_rollup} and record the process's
    // Pss and Private memory usage in 'stats'.  In particular, the method only populates the fields
    // of the MemUsage structure that are intended to be used by Android's periodic Pss collection.
    //
    // The method populates the following statistics in order to be fast an efficient.
    //   Pss
    //   Rss
    //   Uss
    //   private_clean
    //   private_dirty
    //   SwapPss
    // All other fields of MemUsage are zeroed.
    bool SmapsOrRollup(MemUsage* stats) const;

    // Used to parse either of /proc/<pid>/{smaps, smaps_rollup} and record the process's
    // Pss.
    // Returns 'true' on success and the value of Pss in the out parameter.
    bool SmapsOrRollupPss(uint64_t* pss) const;

    const std::vector<uint16_t>& SwapOffsets();

    ~ProcMemInfo() = default;

  private:
    bool ReadMaps(bool get_wss);
    bool ReadVmaStats(int pagemap_fd, Vma& vma, bool get_wss);

    pid_t pid_;
    bool get_wss_;
    uint64_t pgflags_;
    uint64_t pgflags_mask_;

    std::vector<Vma> maps_;

    MemUsage usage_;
    std::vector<uint16_t> swap_offsets_;
};

// Makes callback for each 'vma' or 'map' found in file provided. The file is expected to be in the
// same format as /proc/<pid>/smaps. Returns 'false' if the file is malformed.
bool ForEachVmaFromFile(const std::string& path, const VmaCallback& callback);

// Returns if the kernel supports /proc/<pid>/smaps_rollup. Assumes that the
// calling process has access to the /proc/<pid>/smaps_rollup.
// Returns 'false' if the calling process has no permission to read the file if it exists
// of if the file doesn't exist.
bool IsSmapsRollupSupported(pid_t pid);

// Same as ProcMemInfo::SmapsOrRollup but reads the statistics directly
// from a file. The file MUST be in the same format as /proc/<pid>/smaps
// or /proc/<pid>/smaps_rollup
bool SmapsOrRollupFromFile(const std::string& path, MemUsage* stats);

// Same as ProcMemInfo::SmapsOrRollupPss but reads the statistics directly
// from a file and returns total Pss in kB. The file MUST be in the same format
// as /proc/<pid>/smaps or /proc/<pid>/smaps_rollup
bool SmapsOrRollupPssFromFile(const std::string& path, uint64_t* pss);

}  // namespace meminfo
}  // namespace android

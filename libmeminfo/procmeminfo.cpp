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

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/kernel-page-flags.h>
#include <stdio.h>
#include <unistd.h>

#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <utility>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/unique_fd.h>
#include <procinfo/process_map.h>

#include "meminfo_private.h"

namespace android {
namespace meminfo {

static void add_mem_usage(MemUsage* to, const MemUsage& from) {
    to->vss += from.vss;
    to->rss += from.rss;
    to->pss += from.pss;
    to->uss += from.uss;

    to->swap += from.swap;

    to->private_clean += from.private_clean;
    to->private_dirty += from.private_dirty;

    to->shared_clean += from.shared_clean;
    to->shared_dirty += from.shared_dirty;
}

bool ProcMemInfo::ResetWorkingSet(pid_t pid) {
    std::string clear_refs_path = ::android::base::StringPrintf("/proc/%d/clear_refs", pid);
    if (!::android::base::WriteStringToFile("1\n", clear_refs_path)) {
        PLOG(ERROR) << "Failed to write to " << clear_refs_path;
        return false;
    }

    return true;
}

ProcMemInfo::ProcMemInfo(pid_t pid, bool get_wss, uint64_t pgflags, uint64_t pgflags_mask)
    : pid_(pid), get_wss_(get_wss), pgflags_(pgflags), pgflags_mask_(pgflags_mask) {}

const std::vector<Vma>& ProcMemInfo::Maps() {
    if (maps_.empty() && !ReadMaps(get_wss_)) {
        LOG(ERROR) << "Failed to read maps for Process " << pid_;
    }

    return maps_;
}

const MemUsage& ProcMemInfo::Usage() {
    if (get_wss_) {
        LOG(WARNING) << "Trying to read process memory usage for " << pid_
                     << " using invalid object";
        return usage_;
    }

    if (maps_.empty() && !ReadMaps(get_wss_)) {
        LOG(ERROR) << "Failed to get memory usage for Process " << pid_;
    }

    return usage_;
}

const MemUsage& ProcMemInfo::Wss() {
    if (!get_wss_) {
        LOG(WARNING) << "Trying to read process working set for " << pid_
                     << " using invalid object";
        return wss_;
    }

    if (maps_.empty() && !ReadMaps(get_wss_)) {
        LOG(ERROR) << "Failed to get working set for Process " << pid_;
    }

    return wss_;
}

const std::vector<uint16_t>& ProcMemInfo::SwapOffsets() {
    if (get_wss_) {
        LOG(WARNING) << "Trying to read process swap offsets for " << pid_
                     << " using invalid object";
        return swap_offsets_;
    }

    if (maps_.empty() && !ReadMaps(get_wss_)) {
        LOG(ERROR) << "Failed to get swap offsets for Process " << pid_;
    }

    return swap_offsets_;
}

bool ProcMemInfo::ReadMaps(bool get_wss) {
    // Each object reads /proc/<pid>/maps only once. This is done to make sure programs that are
    // running for the lifetime of the system can recycle the objects and don't have to
    // unnecessarily retain and update this object in memory (which can get significantly large).
    // E.g. A program that only needs to reset the working set will never all ->Maps(), ->Usage().
    // E.g. A program that is monitoring smaps_rollup, may never call ->maps(), Usage(), so it
    // doesn't make sense for us to parse and retain unnecessary memory accounting stats by default.
    if (!maps_.empty()) return true;

    // parse and read /proc/<pid>/maps
    std::string maps_file = ::android::base::StringPrintf("/proc/%d/maps", pid_);
    if (!::android::procinfo::ReadMapFile(
                maps_file, [&](uint64_t start, uint64_t end, uint16_t flags, uint64_t pgoff,
                               const char* name) {
                    maps_.emplace_back(Vma(start, end, pgoff, flags, name));
                })) {
        LOG(ERROR) << "Failed to parse " << maps_file;
        maps_.clear();
        return false;
    }

    std::string pagemap_file = ::android::base::StringPrintf("/proc/%d/pagemap", pid_);
    ::android::base::unique_fd pagemap_fd(
            TEMP_FAILURE_RETRY(open(pagemap_file.c_str(), O_RDONLY | O_CLOEXEC)));
    if (pagemap_fd < 0) {
        PLOG(ERROR) << "Failed to open " << pagemap_file;
        return false;
    }

    for (auto& vma : maps_) {
        if (!ReadVmaStats(pagemap_fd.get(), vma, get_wss)) {
            LOG(ERROR) << "Failed to read page map for vma " << vma.name << "[" << vma.start << "-"
                       << vma.end << "]";
            maps_.clear();
            return false;
        }
        if (get_wss) {
            add_mem_usage(&wss_, vma.wss);
        } else {
            add_mem_usage(&usage_, vma.usage);
        }
    }

    return true;
}

bool ProcMemInfo::ReadVmaStats(int pagemap_fd, Vma& vma, bool get_wss) {
    PageAcct& pinfo = PageAcct::Instance();
    uint64_t pagesz = getpagesize();
    uint64_t num_pages = (vma.end - vma.start) / pagesz;

    std::unique_ptr<uint64_t[]> pg_frames(new uint64_t[num_pages]);
    uint64_t first = vma.start / pagesz;
    if (pread64(pagemap_fd, pg_frames.get(), num_pages * sizeof(uint64_t),
                first * sizeof(uint64_t)) < 0) {
        PLOG(ERROR) << "Failed to read page frames from page map for pid: " << pid_;
        return false;
    }

    std::unique_ptr<uint64_t[]> pg_flags(new uint64_t[num_pages]);
    std::unique_ptr<uint64_t[]> pg_counts(new uint64_t[num_pages]);
    for (uint64_t i = 0; i < num_pages; ++i) {
        if (!get_wss) {
            vma.usage.vss += pagesz;
        }
        uint64_t p = pg_frames[i];
        if (!PAGE_PRESENT(p) && !PAGE_SWAPPED(p)) continue;

        if (PAGE_SWAPPED(p)) {
            vma.usage.swap += pagesz;
            swap_offsets_.emplace_back(PAGE_SWAP_OFFSET(p));
            continue;
        }

        uint64_t page_frame = PAGE_PFN(p);
        if (!pinfo.PageFlags(page_frame, &pg_flags[i])) {
            LOG(ERROR) << "Failed to get page flags for " << page_frame << " in process " << pid_;
            swap_offsets_.clear();
            return false;
        }

        // skip unwanted pages from the count
        if ((pg_flags[i] & pgflags_mask_) != pgflags_) continue;

        if (!pinfo.PageMapCount(page_frame, &pg_counts[i])) {
            LOG(ERROR) << "Failed to get page count for " << page_frame << " in process " << pid_;
            swap_offsets_.clear();
            return false;
        }

        // Page was unmapped between the presence check at the beginning of the loop and here.
        if (pg_counts[i] == 0) {
            pg_frames[i] = 0;
            pg_flags[i] = 0;
            continue;
        }

        bool is_dirty = !!(pg_flags[i] & (1 << KPF_DIRTY));
        bool is_private = (pg_counts[i] == 1);
        // Working set
        if (get_wss) {
            bool is_referenced = !!(pg_flags[i] & (1 << KPF_REFERENCED));
            if (!is_referenced) {
                continue;
            }
            // This effectively makes vss = rss for the working set is requested.
            // The libpagemap implementation returns vss > rss for
            // working set, which doesn't make sense.
            vma.wss.vss += pagesz;
            vma.wss.rss += pagesz;
            vma.wss.uss += is_private ? pagesz : 0;
            vma.wss.pss += pagesz / pg_counts[i];
            if (is_private) {
                vma.wss.private_dirty += is_dirty ? pagesz : 0;
                vma.wss.private_clean += is_dirty ? 0 : pagesz;
            } else {
                vma.wss.shared_dirty += is_dirty ? pagesz : 0;
                vma.wss.shared_clean += is_dirty ? 0 : pagesz;
            }
        } else {
            vma.usage.rss += pagesz;
            vma.usage.uss += is_private ? pagesz : 0;
            vma.usage.pss += pagesz / pg_counts[i];
            if (is_private) {
                vma.usage.private_dirty += is_dirty ? pagesz : 0;
                vma.usage.private_clean += is_dirty ? 0 : pagesz;
            } else {
                vma.usage.shared_dirty += is_dirty ? pagesz : 0;
                vma.usage.shared_clean += is_dirty ? 0 : pagesz;
            }
        }
    }

    return true;
}

}  // namespace meminfo
}  // namespace android

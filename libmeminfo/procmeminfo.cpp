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

#include <atomic>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
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

// Returns true if the line was valid smaps stats line false otherwise.
static bool parse_smaps_field(const char* line, MemUsage* stats) {
    char field[64];
    int len;
    if (sscanf(line, "%63s %n", field, &len) == 1 && *field && field[strlen(field) - 1] == ':') {
        const char* c = line + len;
        switch (field[0]) {
            case 'P':
                if (strncmp(field, "Pss:", 4) == 0) {
                    stats->pss = strtoull(c, nullptr, 10);
                } else if (strncmp(field, "Private_Clean:", 14) == 0) {
                    uint64_t prcl = strtoull(c, nullptr, 10);
                    stats->private_clean = prcl;
                    stats->uss += prcl;
                } else if (strncmp(field, "Private_Dirty:", 14) == 0) {
                    uint64_t prdi = strtoull(c, nullptr, 10);
                    stats->private_dirty = prdi;
                    stats->uss += prdi;
                }
                break;
            case 'S':
                if (strncmp(field, "Size:", 5) == 0) {
                    stats->vss = strtoull(c, nullptr, 10);
                } else if (strncmp(field, "Shared_Clean:", 13) == 0) {
                    stats->shared_clean = strtoull(c, nullptr, 10);
                } else if (strncmp(field, "Shared_Dirty:", 13) == 0) {
                    stats->shared_dirty = strtoull(c, nullptr, 10);
                } else if (strncmp(field, "Swap:", 5) == 0) {
                    stats->swap = strtoull(c, nullptr, 10);
                } else if (strncmp(field, "SwapPss:", 8) == 0) {
                    stats->swap_pss = strtoull(c, nullptr, 10);
                }
                break;
            case 'R':
                if (strncmp(field, "Rss:", 4) == 0) {
                    stats->rss = strtoull(c, nullptr, 10);
                }
                break;
        }
        return true;
    }

    return false;
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

const std::vector<Vma>& ProcMemInfo::MapsWithPageIdle() {
    if (maps_.empty() && !ReadMaps(get_wss_, true)) {
        LOG(ERROR) << "Failed to read maps with page idle for Process " << pid_;
    }

    return maps_;
}

const std::vector<Vma>& ProcMemInfo::Smaps(const std::string& path) {
    if (!maps_.empty()) {
        return maps_;
    }

    auto collect_vmas = [&](const Vma& vma) { maps_.emplace_back(vma); };
    if (path.empty() && !ForEachVma(collect_vmas)) {
        LOG(ERROR) << "Failed to read smaps for Process " << pid_;
        maps_.clear();
    }

    if (!path.empty() && !ForEachVmaFromFile(path, collect_vmas)) {
        LOG(ERROR) << "Failed to read smaps from file " << path;
        maps_.clear();
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
        return usage_;
    }

    if (maps_.empty() && !ReadMaps(get_wss_)) {
        LOG(ERROR) << "Failed to get working set for Process " << pid_;
    }

    return usage_;
}

bool ProcMemInfo::ForEachVma(const VmaCallback& callback) {
    std::string path = ::android::base::StringPrintf("/proc/%d/smaps", pid_);
    return ForEachVmaFromFile(path, callback);
}

bool ProcMemInfo::SmapsOrRollup(MemUsage* stats) const {
    std::string path = ::android::base::StringPrintf(
            "/proc/%d/%s", pid_, IsSmapsRollupSupported(pid_) ? "smaps_rollup" : "smaps");
    return SmapsOrRollupFromFile(path, stats);
}

bool ProcMemInfo::SmapsOrRollupPss(uint64_t* pss) const {
    std::string path = ::android::base::StringPrintf(
            "/proc/%d/%s", pid_, IsSmapsRollupSupported(pid_) ? "smaps_rollup" : "smaps");
    return SmapsOrRollupPssFromFile(path, pss);
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

bool ProcMemInfo::PageMap(const Vma& vma, std::vector<uint64_t>* pagemap) {
    pagemap->clear();
    std::string pagemap_file = ::android::base::StringPrintf("/proc/%d/pagemap", pid_);
    ::android::base::unique_fd pagemap_fd(
            TEMP_FAILURE_RETRY(open(pagemap_file.c_str(), O_RDONLY | O_CLOEXEC)));
    if (pagemap_fd < 0) {
        PLOG(ERROR) << "Failed to open " << pagemap_file;
        return false;
    }

    uint64_t nr_pages = (vma.end - vma.start) / getpagesize();
    pagemap->reserve(nr_pages);

    uint64_t idx = vma.start / getpagesize();
    uint64_t last = idx + nr_pages;
    uint64_t val;
    for (; idx < last; idx++) {
        if (pread64(pagemap_fd, &val, sizeof(uint64_t), idx * sizeof(uint64_t)) < 0) {
            PLOG(ERROR) << "Failed to read page frames from page map for pid: " << pid_;
            return false;
        }
        pagemap->emplace_back(val);
    }

    return true;
}

bool ProcMemInfo::ReadMaps(bool get_wss, bool use_pageidle) {
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
                maps_file, [&](uint64_t start, uint64_t end, uint16_t flags, uint64_t pgoff, ino_t,
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
        if (!ReadVmaStats(pagemap_fd.get(), vma, get_wss, use_pageidle)) {
            LOG(ERROR) << "Failed to read page map for vma " << vma.name << "[" << vma.start << "-"
                       << vma.end << "]";
            maps_.clear();
            return false;
        }
        add_mem_usage(&usage_, vma.usage);
    }

    return true;
}

bool ProcMemInfo::ReadVmaStats(int pagemap_fd, Vma& vma, bool get_wss, bool use_pageidle) {
    PageAcct& pinfo = PageAcct::Instance();
    if (get_wss && use_pageidle && !pinfo.InitPageAcct(true)) {
        LOG(ERROR) << "Failed to init idle page accounting";
        return false;
    }

    uint64_t pagesz = getpagesize();
    size_t num_pages = (vma.end - vma.start) / pagesz;
    size_t first_page = vma.start / pagesz;

    std::vector<uint64_t> page_cache;
    size_t cur_page_cache_index = 0;
    size_t num_in_page_cache = 0;
    size_t num_leftover_pages = num_pages;
    for (size_t cur_page = first_page; cur_page < first_page + num_pages; ++cur_page) {
        if (!get_wss) {
            vma.usage.vss += pagesz;
        }

        // Cache page map data.
        if (cur_page_cache_index == num_in_page_cache) {
            static constexpr size_t kMaxPages = 2048;
            num_leftover_pages -= num_in_page_cache;
            if (num_leftover_pages > kMaxPages) {
                num_in_page_cache = kMaxPages;
            } else {
                num_in_page_cache = num_leftover_pages;
            }
            page_cache.resize(num_in_page_cache);
            size_t total_bytes = page_cache.size() * sizeof(uint64_t);
            ssize_t bytes = pread64(pagemap_fd, page_cache.data(), total_bytes,
                                    cur_page * sizeof(uint64_t));
            if (bytes != total_bytes) {
                if (bytes == -1) {
                    PLOG(ERROR) << "Failed to read page data at offset 0x" << std::hex
                                << cur_page * sizeof(uint64_t);
                } else {
                    LOG(ERROR) << "Failed to read page data at offset 0x" << std::hex
                               << cur_page * sizeof(uint64_t) << std::dec << " read bytes " << bytes
                               << " expected bytes " << total_bytes;
                }
                return false;
            }
            cur_page_cache_index = 0;
        }

        uint64_t page_info = page_cache[cur_page_cache_index++];
        if (!PAGE_PRESENT(page_info) && !PAGE_SWAPPED(page_info)) continue;

        if (PAGE_SWAPPED(page_info)) {
            vma.usage.swap += pagesz;
            swap_offsets_.emplace_back(PAGE_SWAP_OFFSET(page_info));
            continue;
        }

        uint64_t page_frame = PAGE_PFN(page_info);
        uint64_t cur_page_flags;
        if (!pinfo.PageFlags(page_frame, &cur_page_flags)) {
            LOG(ERROR) << "Failed to get page flags for " << page_frame << " in process " << pid_;
            swap_offsets_.clear();
            return false;
        }

        // skip unwanted pages from the count
        if ((cur_page_flags & pgflags_mask_) != pgflags_) continue;

        uint64_t cur_page_counts;
        if (!pinfo.PageMapCount(page_frame, &cur_page_counts)) {
            LOG(ERROR) << "Failed to get page count for " << page_frame << " in process " << pid_;
            swap_offsets_.clear();
            return false;
        }

        // Page was unmapped between the presence check at the beginning of the loop and here.
        if (cur_page_counts == 0) {
            continue;
        }

        bool is_dirty = !!(cur_page_flags & (1 << KPF_DIRTY));
        bool is_private = (cur_page_counts == 1);
        // Working set
        if (get_wss) {
            bool is_referenced = use_pageidle ? (pinfo.IsPageIdle(page_frame) == 1)
                                              : !!(cur_page_flags & (1 << KPF_REFERENCED));
            if (!is_referenced) {
                continue;
            }
            // This effectively makes vss = rss for the working set is requested.
            // The libpagemap implementation returns vss > rss for
            // working set, which doesn't make sense.
            vma.usage.vss += pagesz;
        }

        vma.usage.rss += pagesz;
        vma.usage.uss += is_private ? pagesz : 0;
        vma.usage.pss += pagesz / cur_page_counts;
        if (is_private) {
            vma.usage.private_dirty += is_dirty ? pagesz : 0;
            vma.usage.private_clean += is_dirty ? 0 : pagesz;
        } else {
            vma.usage.shared_dirty += is_dirty ? pagesz : 0;
            vma.usage.shared_clean += is_dirty ? 0 : pagesz;
        }
    }
    return true;
}

// Public APIs
bool ForEachVmaFromFile(const std::string& path, const VmaCallback& callback) {
    auto fp = std::unique_ptr<FILE, decltype(&fclose)>{fopen(path.c_str(), "re"), fclose};
    if (fp == nullptr) {
        return false;
    }

    char* line = nullptr;
    bool parsing_vma = false;
    ssize_t line_len;
    size_t line_alloc = 0;
    Vma vma;
    while ((line_len = getline(&line, &line_alloc, fp.get())) > 0) {
        // Make sure the line buffer terminates like a C string for ReadMapFile
        line[line_len] = '\0';

        if (parsing_vma) {
            if (parse_smaps_field(line, &vma.usage)) {
                // This was a stats field
                continue;
            }

            // Done collecting stats, make the call back
            callback(vma);
            parsing_vma = false;
        }

        vma.clear();
        // If it has, we are looking for the vma stats
        // 00400000-00409000 r-xp 00000000 fc:00 426998  /usr/lib/gvfs/gvfsd-http
        if (!::android::procinfo::ReadMapFileContent(
                    line, [&](uint64_t start, uint64_t end, uint16_t flags, uint64_t pgoff, ino_t,
                              const char* name) {
                        vma.start = start;
                        vma.end = end;
                        vma.flags = flags;
                        vma.offset = pgoff;
                        vma.name = name;
                    })) {
            LOG(ERROR) << "Failed to parse " << path;
            return false;
        }
        parsing_vma = true;
    }

    // free getline() managed buffer
    free(line);

    if (parsing_vma) {
        callback(vma);
    }

    return true;
}

enum smaps_rollup_support { UNTRIED, SUPPORTED, UNSUPPORTED };

static std::atomic<smaps_rollup_support> g_rollup_support = UNTRIED;

bool IsSmapsRollupSupported(pid_t pid) {
    // Similar to OpenSmapsOrRollup checks from android_os_Debug.cpp, except
    // the method only checks if rollup is supported and returns the status
    // right away.
    enum smaps_rollup_support rollup_support = g_rollup_support.load(std::memory_order_relaxed);
    if (rollup_support != UNTRIED) {
        return rollup_support == SUPPORTED;
    }
    std::string rollup_file = ::android::base::StringPrintf("/proc/%d/smaps_rollup", pid);
    if (access(rollup_file.c_str(), F_OK | R_OK)) {
        // No check for errno = ENOENT necessary here. The caller MUST fallback to
        // using /proc/<pid>/smaps instead anyway.
        g_rollup_support.store(UNSUPPORTED, std::memory_order_relaxed);
        return false;
    }

    g_rollup_support.store(SUPPORTED, std::memory_order_relaxed);
    LOG(INFO) << "Using smaps_rollup for pss collection";
    return true;
}

bool SmapsOrRollupFromFile(const std::string& path, MemUsage* stats) {
    auto fp = std::unique_ptr<FILE, decltype(&fclose)>{fopen(path.c_str(), "re"), fclose};
    if (fp == nullptr) {
        return false;
    }

    char* line = nullptr;
    size_t line_alloc = 0;
    stats->clear();
    while (getline(&line, &line_alloc, fp.get()) > 0) {
        switch (line[0]) {
            case 'P':
                if (strncmp(line, "Pss:", 4) == 0) {
                    char* c = line + 4;
                    stats->pss += strtoull(c, nullptr, 10);
                } else if (strncmp(line, "Private_Clean:", 14) == 0) {
                    char* c = line + 14;
                    uint64_t prcl = strtoull(c, nullptr, 10);
                    stats->private_clean += prcl;
                    stats->uss += prcl;
                } else if (strncmp(line, "Private_Dirty:", 14) == 0) {
                    char* c = line + 14;
                    uint64_t prdi = strtoull(c, nullptr, 10);
                    stats->private_dirty += prdi;
                    stats->uss += prdi;
                }
                break;
            case 'R':
                if (strncmp(line, "Rss:", 4) == 0) {
                    char* c = line + 4;
                    stats->rss += strtoull(c, nullptr, 10);
                }
                break;
            case 'S':
                if (strncmp(line, "SwapPss:", 8) == 0) {
                    char* c = line + 8;
                    stats->swap_pss += strtoull(c, nullptr, 10);
                }
                break;
        }
    }

    // free getline() managed buffer
    free(line);
    return true;
}

bool SmapsOrRollupPssFromFile(const std::string& path, uint64_t* pss) {
    auto fp = std::unique_ptr<FILE, decltype(&fclose)>{fopen(path.c_str(), "re"), fclose};
    if (fp == nullptr) {
        return false;
    }
    *pss = 0;
    char* line = nullptr;
    size_t line_alloc = 0;
    while (getline(&line, &line_alloc, fp.get()) > 0) {
        uint64_t v;
        if (sscanf(line, "Pss: %" SCNu64 " kB", &v) == 1) {
            *pss += v;
        }
    }

    // free getline() managed buffer
    free(line);
    return true;
}

}  // namespace meminfo
}  // namespace android

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
#include <unistd.h>

#include <android-base/logging.h>
#include <android-base/unique_fd.h>

#include "meminfo_private.h"

using unique_fd = ::android::base::unique_fd;

namespace android {
namespace meminfo {

static inline off64_t pfn_to_idle_bitmap_offset(uint64_t pfn) {
    return static_cast<off64_t>((pfn >> 6) << 3);
}

uint64_t pagesize(void) {
    static uint64_t pagesize = sysconf(_SC_PAGE_SIZE);
    return pagesize;
}

bool PageAcct::InitPageAcct(bool pageidle_enable) {
    if (pageidle_enable && !PageAcct::KernelHasPageIdle()) {
        LOG(ERROR) << "Idle page tracking is not supported by the kernel";
        return false;
    }

    if (kpagecount_fd_ < 0) {
        unique_fd count_fd(TEMP_FAILURE_RETRY(open("/proc/kpagecount", O_RDONLY | O_CLOEXEC)));
        if (count_fd < 0) {
            PLOG(ERROR) << "Failed to open /proc/kpagecount";
            return false;
        }
        kpagecount_fd_ = std::move(count_fd);
    }

    if (kpageflags_fd_ < 0) {
        unique_fd flags_fd(TEMP_FAILURE_RETRY(open("/proc/kpageflags", O_RDONLY | O_CLOEXEC)));
        if (flags_fd < 0) {
            PLOG(ERROR) << "Failed to open /proc/kpageflags";
            return false;
        }
        kpageflags_fd_ = std::move(flags_fd);
    }

    if (pageidle_enable && pageidle_fd_ < 0) {
        unique_fd idle_fd(
                TEMP_FAILURE_RETRY(open("/sys/kernel/mm/page_idle/bitmap", O_RDWR | O_CLOEXEC)));
        if (idle_fd < 0) {
            PLOG(ERROR) << "Failed to open page idle bitmap";
            return false;
        }
        pageidle_fd_ = std::move(idle_fd);
    }

    return true;
}

bool PageAcct::PageFlags(uint64_t pfn, uint64_t* flags) {
    if (!flags) return false;

    if (kpageflags_fd_ < 0) {
        if (!InitPageAcct()) return false;
    }

    if (pread64(kpageflags_fd_, flags, sizeof(uint64_t), pfn * sizeof(uint64_t)) < 0) {
        PLOG(ERROR) << "Failed to read page flags for page " << pfn;
        return false;
    }
    return true;
}

bool PageAcct::PageMapCount(uint64_t pfn, uint64_t* mapcount) {
    if (!mapcount) return false;

    if (kpagecount_fd_ < 0) {
        if (!InitPageAcct()) return false;
    }

    if (pread64(kpagecount_fd_, mapcount, sizeof(uint64_t), pfn * sizeof(uint64_t)) < 0) {
        PLOG(ERROR) << "Failed to read map count for page " << pfn;
        return false;
    }
    return true;
}

int PageAcct::IsPageIdle(uint64_t pfn) {
    if (pageidle_fd_ < 0) {
        if (!InitPageAcct(true)) return -EOPNOTSUPP;
    }

    int idle_status = MarkPageIdle(pfn);
    if (idle_status) return idle_status;

    return GetPageIdle(pfn);
}

int PageAcct::MarkPageIdle(uint64_t pfn) const {
    off64_t offset = pfn_to_idle_bitmap_offset(pfn);
    // set the bit corresponding to page frame
    uint64_t idle_bits = 1ULL << (pfn % 64);

    if (pwrite64(pageidle_fd_, &idle_bits, sizeof(uint64_t), offset) < 0) {
        PLOG(ERROR) << "Failed to write page idle bitmap for page " << pfn;
        return -errno;
    }

    return 0;
}

int PageAcct::GetPageIdle(uint64_t pfn) const {
    off64_t offset = pfn_to_idle_bitmap_offset(pfn);
    uint64_t idle_bits;

    if (pread64(pageidle_fd_, &idle_bits, sizeof(uint64_t), offset) < 0) {
        PLOG(ERROR) << "Failed to read page idle bitmap for page " << pfn;
        return -errno;
    }

    return !!(idle_bits & (1ULL << (pfn % 64)));
}

// Public methods
bool page_present(uint64_t pagemap_val) {
    return PAGE_PRESENT(pagemap_val);
}

bool page_swapped(uint64_t pagemap_val) {
    return PAGE_SWAPPED(pagemap_val);
}

uint64_t page_pfn(uint64_t pagemap_val) {
    return PAGE_PFN(pagemap_val);
}

}  // namespace meminfo
}  // namespace android

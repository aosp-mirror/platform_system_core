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
#include <unistd.h>

#include <string>
#include <vector>

#include <android-base/unique_fd.h>

namespace android {
namespace meminfo {

class PageAcct final {
    // Class for per-page accounting by using kernel provided interfaces like
    // kpagecount, kpageflags etc.
  public:
    static bool KernelHasPageIdle() {
        return (access("/sys/kernel/mm/page_idle/bitmap", R_OK | W_OK) == 0);
    }

    bool InitPageAcct(bool pageidle_enable = false);
    bool PageFlags(uint64_t pfn, uint64_t* flags);
    bool PageMapCount(uint64_t pfn, uint64_t* mapcount);

    int IsPageIdle(uint64_t pfn);

    // The only way to create PageAcct object
    static PageAcct& Instance() {
        static PageAcct instance;
        return instance;
    }

    ~PageAcct() = default;

  private:
    PageAcct() : kpagecount_fd_(-1), kpageflags_fd_(-1), pageidle_fd_(-1) {}
    int MarkPageIdle(uint64_t pfn) const;
    int GetPageIdle(uint64_t pfn) const;

    // Non-copyable & Non-movable
    PageAcct(const PageAcct&) = delete;
    PageAcct& operator=(const PageAcct&) = delete;
    PageAcct& operator=(PageAcct&&) = delete;
    PageAcct(PageAcct&&) = delete;

    ::android::base::unique_fd kpagecount_fd_;
    ::android::base::unique_fd kpageflags_fd_;
    ::android::base::unique_fd pageidle_fd_;
};

// Returns if the page present bit is set in the value
// passed in.
bool page_present(uint64_t pagemap_val);

// Returns if the page swapped bit is set in the value
// passed in.
bool page_swapped(uint64_t pagemap_val);

// Returns the page frame number (physical page) from
// pagemap value
uint64_t page_pfn(uint64_t pagemap_val);

}  // namespace meminfo
}  // namespace android

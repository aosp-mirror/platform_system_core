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

#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <string>
#include <vector>

namespace android {
namespace meminfo {

struct MemUsage {
    uint64_t vss;
    uint64_t rss;
    uint64_t pss;
    uint64_t uss;

    uint64_t swap;
    uint64_t swap_pss;

    uint64_t private_clean;
    uint64_t private_dirty;
    uint64_t shared_clean;
    uint64_t shared_dirty;

    MemUsage()
        : vss(0),
          rss(0),
          pss(0),
          uss(0),
          swap(0),
          swap_pss(0),
          private_clean(0),
          private_dirty(0),
          shared_clean(0),
          shared_dirty(0) {}

    ~MemUsage() = default;

    void clear() {
        vss = rss = pss = uss = swap = swap_pss = 0;
        private_clean = private_dirty = shared_clean = shared_dirty = 0;
    }
};

struct Vma {
    uint64_t start;
    uint64_t end;
    uint64_t offset;
    uint16_t flags;
    std::string name;

    Vma() : start(0), end(0), offset(0), flags(0), name("") {}
    Vma(uint64_t s, uint64_t e, uint64_t off, uint16_t f, const char* n)
        : start(s), end(e), offset(off), flags(f), name(n) {}
    ~Vma() = default;

    void clear() { memset(&usage, 0, sizeof(usage)); }

    // Memory usage of this mapping.
    MemUsage usage;
};

}  // namespace meminfo
}  // namespace android

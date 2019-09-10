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

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>

#include "meminfo_private.h"

namespace android {
namespace meminfo {

bool SysMemInfo::ReadMemInfo(const char* path) {
    return ReadMemInfo(path, SysMemInfo::kDefaultSysMemInfoTags.size(),
                       &*SysMemInfo::kDefaultSysMemInfoTags.begin(),
                       [&](std::string_view tag, uint64_t val) {
                           // Safe to store the string_view in the map
                           // because the tags from
                           // kDefaultSysMemInfoTags are all
                           // statically-allocated.
                           mem_in_kb_[tag] = val;
                       });
}

bool SysMemInfo::ReadMemInfo(std::vector<uint64_t>* out, const char* path) {
    out->clear();
    out->resize(SysMemInfo::kDefaultSysMemInfoTags.size());
    return ReadMemInfo(SysMemInfo::kDefaultSysMemInfoTags.size(),
                       &*SysMemInfo::kDefaultSysMemInfoTags.begin(), out->data(), path);
}

bool SysMemInfo::ReadMemInfo(size_t ntags, const std::string_view* tags, uint64_t* out,
                             const char* path) {
    return ReadMemInfo(path, ntags, tags, [&]([[maybe_unused]] std::string_view tag, uint64_t val) {
        auto it = std::find(tags, tags + ntags, tag);
        if (it == tags + ntags) {
            LOG(ERROR) << "Tried to store invalid tag: " << tag;
            return;
        }
        auto index = std::distance(tags, it);
        // store the values in the same order as the tags
        out[index] = val;
    });
}

uint64_t SysMemInfo::ReadVmallocInfo() {
    return ::android::meminfo::ReadVmallocInfo();
}

bool SysMemInfo::ReadMemInfo(const char* path, size_t ntags, const std::string_view* tags,
                             std::function<void(std::string_view, uint64_t)> store_val) {
    char buffer[4096];
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        PLOG(ERROR) << "Failed to open file :" << path;
        return false;
    }

    const int len = read(fd, buffer, sizeof(buffer) - 1);
    close(fd);
    if (len < 0) {
        return false;
    }

    buffer[len] = '\0';
    char* p = buffer;
    uint32_t found = 0;
    uint32_t lineno = 0;
    bool zram_tag_found = false;
    while (*p && found < ntags) {
        for (size_t tagno = 0; tagno < ntags; ++tagno) {
            const std::string_view& tag = tags[tagno];
            // Special case for "Zram:" tag that android_os_Debug and friends look
            // up along with the rest of the numbers from /proc/meminfo
            if (!zram_tag_found && tag == "Zram:") {
                store_val(tag, mem_zram_kb());
                zram_tag_found = true;
                found++;
                continue;
            }

            if (strncmp(p, tag.data(), tag.size()) == 0) {
                p += tag.size();
                while (*p == ' ') p++;
                char* endptr = nullptr;
                uint64_t val = strtoull(p, &endptr, 10);
                if (p == endptr) {
                    PLOG(ERROR) << "Failed to parse line:" << lineno + 1 << " in file: " << path;
                    return false;
                }
                store_val(tag, val);
                p = endptr;
                found++;
                break;
            }
        }

        while (*p && *p != '\n') {
            p++;
        }
        if (*p) p++;
        lineno++;
    }

    return true;
}

uint64_t SysMemInfo::mem_zram_kb(const char* zram_dev_cstr) {
    uint64_t mem_zram_total = 0;
    if (zram_dev_cstr) {
        if (!MemZramDevice(zram_dev_cstr, &mem_zram_total)) {
            return 0;
        }
        return mem_zram_total / 1024;
    }

    constexpr uint32_t kMaxZramDevices = 256;
    for (uint32_t i = 0; i < kMaxZramDevices; i++) {
        std::string zram_dev_abspath = ::android::base::StringPrintf("/sys/block/zram%u/", i);
        if (access(zram_dev_abspath.c_str(), F_OK)) {
            // We assume zram devices appear in range 0-255 and appear always in sequence
            // under /sys/block. So, stop looking for them once we find one is missing.
            break;
        }

        uint64_t mem_zram_dev;
        if (!MemZramDevice(zram_dev_abspath.c_str(), &mem_zram_dev)) {
            return 0;
        }

        mem_zram_total += mem_zram_dev;
    }

    return mem_zram_total / 1024;
}

bool SysMemInfo::MemZramDevice(const char* zram_dev, uint64_t* mem_zram_dev) {
    std::string mmstat = ::android::base::StringPrintf("%s/%s", zram_dev, "mm_stat");
    auto mmstat_fp = std::unique_ptr<FILE, decltype(&fclose)>{fopen(mmstat.c_str(), "re"), fclose};
    if (mmstat_fp != nullptr) {
        // only if we do have mmstat, use it. Otherwise, fall through to trying out the old
        // 'mem_used_total'
        if (fscanf(mmstat_fp.get(), "%*" SCNu64 " %*" SCNu64 " %" SCNu64, mem_zram_dev) != 1) {
            PLOG(ERROR) << "Malformed mm_stat file in: " << zram_dev;
            return false;
        }
        return true;
    }

    std::string content;
    if (::android::base::ReadFileToString(
                ::android::base::StringPrintf("%s/mem_used_total", zram_dev), &content)) {
        *mem_zram_dev = strtoull(content.c_str(), NULL, 10);
        if (*mem_zram_dev == ULLONG_MAX) {
            PLOG(ERROR) << "Malformed mem_used_total file for zram dev: " << zram_dev
                        << " content: " << content;
            return false;
        }

        return true;
    }

    LOG(ERROR) << "Can't find memory status under: " << zram_dev;
    return false;
}

// Public methods
uint64_t ReadVmallocInfo(const char* path) {
    uint64_t vmalloc_total = 0;
    auto fp = std::unique_ptr<FILE, decltype(&fclose)>{fopen(path, "re"), fclose};
    if (fp == nullptr) {
        return vmalloc_total;
    }

    char* line = nullptr;
    size_t line_alloc = 0;
    while (getline(&line, &line_alloc, fp.get()) > 0) {
        // We are looking for lines like
        //
        // 0x0000000000000000-0x0000000000000000   12288 drm_property_create_blob+0x44/0xec pages=2 vmalloc
        // 0x0000000000000000-0x0000000000000000    8192 wlan_logging_sock_init_svc+0xf8/0x4f0 [wlan] pages=1 vmalloc
        //
        // Notice that if the caller is coming from a module, the kernel prints and extra
        // "[module_name]" after the address and the symbol of the call site. This means we can't
        // use the old sscanf() method of getting the # of pages.
        char* p_start = strstr(line, "pages=");
        if (p_start == nullptr) {
            // we didn't find anything
            continue;
        }

        uint64_t nr_pages;
        if (sscanf(p_start, "pages=%" SCNu64 "", &nr_pages) == 1) {
            vmalloc_total += (nr_pages * getpagesize());
        }
    }

    free(line);

    return vmalloc_total;
}

}  // namespace meminfo
}  // namespace android

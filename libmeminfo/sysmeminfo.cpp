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

const std::vector<std::string> SysMemInfo::kDefaultSysMemInfoTags = {
        SysMemInfo::kMemTotal,      SysMemInfo::kMemFree,        SysMemInfo::kMemBuffers,
        SysMemInfo::kMemCached,     SysMemInfo::kMemShmem,       SysMemInfo::kMemSlab,
        SysMemInfo::kMemSReclaim,   SysMemInfo::kMemSUnreclaim,  SysMemInfo::kMemSwapTotal,
        SysMemInfo::kMemSwapFree,   SysMemInfo::kMemMapped,      SysMemInfo::kMemVmallocUsed,
        SysMemInfo::kMemPageTables, SysMemInfo::kMemKernelStack,
};

bool SysMemInfo::ReadMemInfo(const std::string& path) {
    return ReadMemInfo(SysMemInfo::kDefaultSysMemInfoTags, path,
                       [&](const std::string& tag, uint64_t val) { mem_in_kb_[tag] = val; });
}

bool SysMemInfo::ReadMemInfo(std::vector<uint64_t>* out, const std::string& path) {
    return ReadMemInfo(SysMemInfo::kDefaultSysMemInfoTags, out, path);
}

bool SysMemInfo::ReadMemInfo(const std::vector<std::string>& tags, std::vector<uint64_t>* out,
                             const std::string& path) {
    out->clear();
    out->resize(tags.size());

    return ReadMemInfo(tags, path, [&]([[maybe_unused]] const std::string& tag, uint64_t val) {
        auto it = std::find(tags.begin(), tags.end(), tag);
        if (it == tags.end()) {
            LOG(ERROR) << "Tried to store invalid tag: " << tag;
            return;
        }
        auto index = std::distance(tags.begin(), it);
        // store the values in the same order as the tags
        out->at(index) = val;
    });
}

uint64_t SysMemInfo::ReadVmallocInfo(const std::string& path) {
    uint64_t vmalloc_total = 0;
    auto fp = std::unique_ptr<FILE, decltype(&fclose)>{fopen(path.c_str(), "re"), fclose};
    if (fp == nullptr) {
        return vmalloc_total;
    }

    char line[1024];
    while (fgets(line, 1024, fp.get()) != nullptr) {
        // We are looking for lines like
        // 0x0000000000000000-0x0000000000000000   12288 drm_property_create_blob+0x44/0xec pages=2
        // vmalloc 0x0000000000000000-0x0000000000000000    8192
        // wlan_logging_sock_init_svc+0xf8/0x4f0 [wlan] pages=1 vmalloc Notice that if the caller is
        // coming from a module, the kernel prints and extra "[module_name]" after the address and
        // the symbol of the call site. This means we can't use the old sscanf() method of getting
        // the # of pages.
        char* p_start = strstr(line, "pages=");
        if (p_start == nullptr) {
            // we didn't find anything
            continue;
        }

        p_start = strtok(p_start, " ");
        long nr_pages;
        if (sscanf(p_start, "pages=%ld", &nr_pages) == 1) {
            vmalloc_total += (nr_pages * getpagesize());
        }
    }

    return vmalloc_total;
}

// TODO: Delete this function if it can't match up with the c-like implementation below.
// Currently, this added about 50 % extra overhead on hikey.
#if 0
bool SysMemInfo::ReadMemInfo(const std::vector<std::string>& tags, const std::string& path) {
    std::string buffer;
    if (!::android::base::ReadFileToString(path, &buffer)) {
        PLOG(ERROR) << "Failed to read : " << path;
        return false;
    }

    uint32_t total_found = 0;
    for (auto s = buffer.begin(); s < buffer.end() && total_found < tags.size();) {
        for (auto& tag : tags) {
            if (tag == std::string(s, s + tag.size())) {
                s += tag.size();
                while (isspace(*s)) s++;
                auto num_start = s;
                while (std::isdigit(*s)) s++;

                std::string number(num_start, num_start + (s - num_start));
                if (!::android::base::ParseUint(number, &mem_in_kb_[tag])) {
                    LOG(ERROR) << "Failed to parse uint";
                    return false;
                }
                total_found++;
                break;
            }
        }
        while (s < buffer.end() && *s != '\n') s++;
        if (s < buffer.end()) s++;
    }

    return true;
}

#else
bool SysMemInfo::ReadMemInfo(const std::vector<std::string>& tags, const std::string& path,
                             std::function<void(const std::string&, uint64_t)> store_val) {
    char buffer[4096];
    int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
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
    while (*p && found < tags.size()) {
        for (auto& tag : tags) {
            // Special case for "Zram:" tag that android_os_Debug and friends look
            // up along with the rest of the numbers from /proc/meminfo
            if (!zram_tag_found && tag == "Zram:") {
                store_val(tag, mem_zram_kb());
                zram_tag_found = true;
                found++;
                continue;
            }

            if (strncmp(p, tag.c_str(), tag.size()) == 0) {
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
#endif

uint64_t SysMemInfo::mem_zram_kb(const std::string& zram_dev) {
    uint64_t mem_zram_total = 0;
    if (!zram_dev.empty()) {
        if (!MemZramDevice(zram_dev, &mem_zram_total)) {
            return 0;
        }
        return mem_zram_total / 1024;
    }

    constexpr uint32_t kMaxZramDevices = 256;
    for (uint32_t i = 0; i < kMaxZramDevices; i++) {
        std::string zram_dev = ::android::base::StringPrintf("/sys/block/zram%u/", i);
        if (access(zram_dev.c_str(), F_OK)) {
            // We assume zram devices appear in range 0-255 and appear always in sequence
            // under /sys/block. So, stop looking for them once we find one is missing.
            break;
        }

        uint64_t mem_zram_dev;
        if (!MemZramDevice(zram_dev, &mem_zram_dev)) {
            return 0;
        }

        mem_zram_total += mem_zram_dev;
    }

    return mem_zram_total / 1024;
}

bool SysMemInfo::MemZramDevice(const std::string& zram_dev, uint64_t* mem_zram_dev) {
    std::string mmstat = ::android::base::StringPrintf("%s/%s", zram_dev.c_str(), "mm_stat");
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
    if (::android::base::ReadFileToString(zram_dev + "mem_used_total", &content)) {
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

}  // namespace meminfo
}  // namespace android

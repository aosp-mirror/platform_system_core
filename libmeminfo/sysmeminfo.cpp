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
#include <stdlib.h>
#include <unistd.h>

#include <cctype>
#include <cstdio>
#include <fstream>
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
    return ReadMemInfo(SysMemInfo::kDefaultSysMemInfoTags, path);
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
bool SysMemInfo::ReadMemInfo(const std::vector<std::string>& tags, const std::string& path) {
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
    while (*p && found < tags.size()) {
        for (auto& tag : tags) {
            if (strncmp(p, tag.c_str(), tag.size()) == 0) {
                p += tag.size();
                while (*p == ' ') p++;
                char* endptr = nullptr;
                mem_in_kb_[tag] = strtoull(p, &endptr, 10);
                if (p == endptr) {
                    PLOG(ERROR) << "Failed to parse line:" << lineno + 1 << " in file: " << path;
                    return false;
                }
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
    std::string content;
    if (android::base::ReadFileToString(zram_dev + "mm_stat", &content)) {
        std::vector<std::string> values = ::android::base::Split(content, " ");
        if (values.size() < 3) {
            LOG(ERROR) << "Malformed mm_stat file for zram dev: " << zram_dev
                       << " content: " << content;
            return false;
        }

        if (!::android::base::ParseUint(values[2], mem_zram_dev)) {
            LOG(ERROR) << "Malformed mm_stat file for zram dev: " << zram_dev
                       << " value: " << values[2];
            return false;
        }

        return true;
    }

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

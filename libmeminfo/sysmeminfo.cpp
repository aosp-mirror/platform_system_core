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
#include <stdlib.h>
#include <unistd.h>

#include <cctype>
#include <fstream>
#include <string>
#include <utility>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/strings.h>

#include "meminfo_private.h"

namespace android {
namespace meminfo {

const std::vector<std::string> SysMemInfo::kDefaultSysMemInfoTags = {
    "MemTotal:", "MemFree:",      "Buffers:",     "Cached:",     "Shmem:",
    "Slab:",     "SReclaimable:", "SUnreclaim:",  "SwapTotal:",  "SwapFree:",
    "ZRam:",     "Mapped:",       "VmallocUsed:", "PageTables:", "KernelStack:",
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
    while (*p && found < tags.size()) {
        for (auto& tag : tags) {
            if (strncmp(p, tag.c_str(), tag.size()) == 0) {
                p += tag.size();
                while (*p == ' ') p++;
                char* endptr = nullptr;
                mem_in_kb_[tag] = strtoull(p, &endptr, 10);
                if (p == endptr) {
                    PLOG(ERROR) << "Failed to parse line in file: " << path;
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
    }

    return true;
}
#endif

}  // namespace meminfo
}  // namespace android

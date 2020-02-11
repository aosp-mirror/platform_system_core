/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include "util.h"

#include <dirent.h>
#include <sys/ioctl.h>
#include <sys/types.h>

#include <thread>

#include <android-base/stringprintf.h>
#include <android-base/unique_fd.h>
#include <linux/fs.h>

namespace android {
namespace fs_mgr {

bool NibbleValue(const char& c, uint8_t* value) {
    CHECK(value != nullptr);

    switch (c) {
        case '0' ... '9':
            *value = c - '0';
            break;
        case 'a' ... 'f':
            *value = c - 'a' + 10;
            break;
        case 'A' ... 'F':
            *value = c - 'A' + 10;
            break;
        default:
            return false;
    }

    return true;
}

bool HexToBytes(uint8_t* bytes, size_t bytes_len, const std::string& hex) {
    CHECK(bytes != nullptr);

    if (hex.size() % 2 != 0) {
        return false;
    }
    if (hex.size() / 2 > bytes_len) {
        return false;
    }
    for (size_t i = 0, j = 0, n = hex.size(); i < n; i += 2, ++j) {
        uint8_t high;
        if (!NibbleValue(hex[i], &high)) {
            return false;
        }
        uint8_t low;
        if (!NibbleValue(hex[i + 1], &low)) {
            return false;
        }
        bytes[j] = (high << 4) | low;
    }
    return true;
}

std::string BytesToHex(const uint8_t* bytes, size_t bytes_len) {
    CHECK(bytes != nullptr);

    static const char* hex_digits = "0123456789abcdef";
    std::string hex;

    for (size_t i = 0; i < bytes_len; i++) {
        hex.push_back(hex_digits[(bytes[i] & 0xF0) >> 4]);
        hex.push_back(hex_digits[bytes[i] & 0x0F]);
    }
    return hex;
}

// TODO: remove duplicate code with fs_mgr_wait_for_file
bool WaitForFile(const std::string& filename, const std::chrono::milliseconds relative_timeout,
                 FileWaitMode file_wait_mode) {
    auto start_time = std::chrono::steady_clock::now();

    while (true) {
        int rv = access(filename.c_str(), F_OK);
        if (file_wait_mode == FileWaitMode::Exists) {
            if (!rv || errno != ENOENT) return true;
        } else if (file_wait_mode == FileWaitMode::DoesNotExist) {
            if (rv && errno == ENOENT) return true;
        }

        std::this_thread::sleep_for(50ms);

        auto now = std::chrono::steady_clock::now();
        auto time_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time);
        if (time_elapsed > relative_timeout) return false;
    }
}

bool IsDeviceUnlocked() {
    std::string verified_boot_state;

    if (fs_mgr_get_boot_config("verifiedbootstate", &verified_boot_state)) {
        return verified_boot_state == "orange";
    }
    return false;
}

bool SetBlockDeviceReadOnly(const std::string& blockdev) {
    android::base::unique_fd fd(TEMP_FAILURE_RETRY(open(blockdev.c_str(), O_RDONLY | O_CLOEXEC)));
    if (fd < 0) {
        return false;
    }

    int ON = 1;
    return ioctl(fd, BLKROSET, &ON) == 0;
}

Result<std::vector<std::string>> ListFiles(const std::string& dir) {
    struct dirent* de;
    std::vector<std::string> files;

    std::unique_ptr<DIR, int (*)(DIR*)> dirp(opendir(dir.c_str()), closedir);
    if (!dirp) {
        return ErrnoError() << "Failed to opendir: " << dir;
    }

    while ((de = readdir(dirp.get()))) {
        if (de->d_type != DT_REG) continue;
        std::string full_path = android::base::StringPrintf("%s/%s", dir.c_str(), de->d_name);
        files.emplace_back(std::move(full_path));
    }

    return files;
}

}  // namespace fs_mgr
}  // namespace android

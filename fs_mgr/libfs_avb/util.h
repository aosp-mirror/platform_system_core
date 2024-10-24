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

#pragma once

#include <chrono>
#include <string>
#include <vector>

#include <android-base/result.h>

using android::base::ErrnoError;
using android::base::Result;

#define FS_AVB_TAG "[libfs_avb] "

// Logs a message to kernel
#define LINFO LOG(INFO) << FS_AVB_TAG
#define LWARNING LOG(WARNING) << FS_AVB_TAG
#define LERROR LOG(ERROR) << FS_AVB_TAG
#define LFATAL LOG(FATAL) << FS_AVB_TAG

// Logs a message with strerror(errno) at the end
#define PINFO PLOG(INFO) << FS_AVB_TAG
#define PWARNING PLOG(WARNING) << FS_AVB_TAG
#define PERROR PLOG(ERROR) << FS_AVB_TAG
#define PFATAL PLOG(FATAL) << FS_AVB_TAG

extern bool fs_mgr_get_boot_config(const std::string& key, std::string* out_val);

using namespace std::chrono_literals;

namespace android {
namespace fs_mgr {

bool NibbleValue(const char& c, uint8_t* value);

bool HexToBytes(uint8_t* bytes, size_t bytes_len, const std::string& hex);

std::string BytesToHex(const uint8_t* bytes, size_t bytes_len);

enum class FileWaitMode { Exists, DoesNotExist };
bool WaitForFile(const std::string& filename, const std::chrono::milliseconds relative_timeout,
                 FileWaitMode wait_mode = FileWaitMode::Exists);

bool IsDeviceUnlocked();

bool SetBlockDeviceReadOnly(const std::string& blockdev);

// Returns a list of file under the dir, no order is guaranteed.
Result<std::vector<std::string>> ListFiles(const std::string& dir);

}  // namespace fs_mgr
}  // namespace android

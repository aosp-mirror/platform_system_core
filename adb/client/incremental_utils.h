/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include "adb_unique_fd.h"

#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <stdint.h>

#include <android-base/off64_t.h>

namespace incremental {

using Size = int64_t;
constexpr int kBlockSize = 4096;
constexpr int kSha256DigestSize = 32;
constexpr int kDigestSize = kSha256DigestSize;
constexpr int kMaxSignatureSize = 8096;  // incrementalfs.h

constexpr std::string_view IDSIG = ".idsig";

std::vector<int32_t> PriorityBlocksForFile(const std::string& filepath, borrowed_fd fd,
                                           Size fileSize);

Size verity_tree_blocks_for_file(Size fileSize);
Size verity_tree_size_for_file(Size fileSize);

std::pair<std::vector<char>, int32_t> read_id_sig_headers(borrowed_fd fd);
std::pair<off64_t, ssize_t> skip_id_sig_headers(borrowed_fd fd);

}  // namespace incremental

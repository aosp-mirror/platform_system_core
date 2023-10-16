// Copyright (C) 2023 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#pragma once

#include <stdint.h>

#include <memory>
#include <optional>
#include <unordered_map>
#include <vector>

#include <android-base/unique_fd.h>
#include <libsnapshot/cow_format.h>

namespace android {
namespace snapshot {

class CowParserV2 {
  public:
    bool Parse(android::base::borrowed_fd fd, const CowHeader& header,
               std::optional<uint64_t> label = {});

    const CowHeader& header() const { return header_; }
    const std::optional<CowFooter>& footer() const { return footer_; }
    std::shared_ptr<std::vector<CowOperationV2>> ops() { return ops_; }
    std::shared_ptr<std::unordered_map<uint64_t, uint64_t>> data_loc() const { return data_loc_; }
    uint64_t fd_size() const { return fd_size_; }
    const std::optional<uint64_t>& last_label() const { return last_label_; }

  private:
    bool ParseOps(android::base::borrowed_fd fd, std::optional<uint64_t> label);

    CowHeader header_ = {};
    std::optional<CowFooter> footer_;
    std::shared_ptr<std::vector<CowOperationV2>> ops_;
    std::shared_ptr<std::unordered_map<uint64_t, uint64_t>> data_loc_;
    uint64_t fd_size_;
    std::optional<uint64_t> last_label_;
};

}  // namespace snapshot
}  // namespace android

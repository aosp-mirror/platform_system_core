//
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
//

#pragma once

#include <optional>
#include <unordered_map>

#include <android-base/unique_fd.h>
#include <libsnapshot/cow_format.h>

namespace android {
namespace snapshot {

struct TranslatedCowOps {
    CowHeaderV3 header;
    std::shared_ptr<std::vector<CowOperationV3>> ops;
};

class CowParserBase {
  public:
    virtual ~CowParserBase() = default;

    virtual bool Parse(android::base::borrowed_fd fd, const CowHeaderV3& header,
                       std::optional<uint64_t> label = {}) = 0;
    virtual bool Translate(TranslatedCowOps* out) = 0;
    virtual std::optional<CowFooter> footer() const { return std::nullopt; }
    std::shared_ptr<std::unordered_map<uint64_t, uint64_t>> xor_data_loc() {
        return xor_data_loc_;
    };

    uint64_t fd_size() const { return fd_size_; }
    const std::optional<uint64_t>& last_label() const { return last_label_; }

  protected:
    CowHeaderV3 header_ = {};
    uint64_t fd_size_;
    std::optional<uint64_t> last_label_;
    std::shared_ptr<std::unordered_map<uint64_t, uint64_t>> xor_data_loc_ = {};
};

}  // namespace snapshot
}  // namespace android

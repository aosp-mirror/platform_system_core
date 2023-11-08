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
#include <libsnapshot_cow/parser_base.h>

namespace android {
namespace snapshot {

class CowParserV3 final : public CowParserBase {
  public:
    bool Parse(android::base::borrowed_fd fd, const CowHeaderV3& header,
               std::optional<uint64_t> label = {}) override;
    bool Translate(TranslatedCowOps* out) override;

  private:
    bool ParseOps(android::base::borrowed_fd fd, std::optional<uint64_t> label);
    off_t GetDataOffset() const;
    CowHeaderV3 header_ = {};
    std::shared_ptr<std::vector<CowOperationV3>> ops_;
};

}  // namespace snapshot
}  // namespace android

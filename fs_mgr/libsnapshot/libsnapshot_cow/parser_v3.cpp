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
#include "parser_v3.h"

#include <android-base/file.h>
#include <android-base/logging.h>

#include <libsnapshot/cow_format.h>

namespace android {
namespace snapshot {

using android::base::borrowed_fd;

bool CowParserV3::Parse(borrowed_fd fd, const CowHeaderV3& header, std::optional<uint64_t> label) {
    LOG(ERROR) << "this function should never be called";
    if (fd.get() || sizeof(header) > 0 || label) return false;
    return false;
}

bool CowParserV3::ParseOps(android::base::borrowed_fd fd, std::optional<uint64_t> label) {
    LOG(ERROR) << "this function should never be called";
    if (fd.get() || label) return false;
    return false;
}

bool CowParserV3::Translate(TranslatedCowOps* out) {
    out->ops = ops_;
    out->header = header_;
    return true;
}

}  // namespace snapshot
}  // namespace android

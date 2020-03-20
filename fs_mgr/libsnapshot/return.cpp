// Copyright (C) 2019 The Android Open Source Project
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

#include <libsnapshot/return.h>

#include <string.h>

using android::fiemap::FiemapStatus;

namespace android::snapshot {

std::string Return::string() const {
    switch (error_code()) {
        case ErrorCode::ERROR:
            return "Error";
        case ErrorCode::SUCCESS:
            [[fallthrough]];
        case ErrorCode::NO_SPACE:
            return strerror(-static_cast<int>(error_code()));
    }
}

Return::ErrorCode Return::FromFiemapStatusErrorCode(FiemapStatus::ErrorCode error_code) {
    switch (error_code) {
        case FiemapStatus::ErrorCode::SUCCESS:
        case FiemapStatus::ErrorCode::ERROR:
        case FiemapStatus::ErrorCode::NO_SPACE:
            return static_cast<ErrorCode>(error_code);
        default:
            return ErrorCode::ERROR;
    }
}
}  // namespace android::snapshot

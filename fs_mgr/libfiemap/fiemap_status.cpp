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

#include <libfiemap/fiemap_status.h>

namespace android::fiemap {

// FiemapStatus -> string
std::string FiemapStatus::string() const {
    if (error_code() == ErrorCode::ERROR) {
        return "Error";
    }
    return strerror(-static_cast<int>(error_code()));
}

// -errno -> known ErrorCode
// unknown ErrorCode -> known ErrorCode
FiemapStatus::ErrorCode FiemapStatus::CastErrorCode(int error_code) {
    switch (error_code) {
        case static_cast<int32_t>(ErrorCode::SUCCESS):
        case static_cast<int32_t>(ErrorCode::NO_SPACE):
            return static_cast<ErrorCode>(error_code);
        case static_cast<int32_t>(ErrorCode::ERROR):
        default:
            return ErrorCode::ERROR;
    }
}

}  // namespace android::fiemap

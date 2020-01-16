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

#pragma once

#include <stdint.h>
#include <string.h>

#include <libfiemap/fiemap_status.h>

namespace android::snapshot {

// SnapshotManager functions return either bool or Return objects. "Return" types provides
// more information about the reason of the failure.
class Return {
    using FiemapStatus = android::fiemap::FiemapStatus;

  public:
    enum class ErrorCode : int32_t {
        SUCCESS = static_cast<int32_t>(FiemapStatus::ErrorCode::SUCCESS),
        ERROR = static_cast<int32_t>(FiemapStatus::ErrorCode::ERROR),
        NO_SPACE = static_cast<int32_t>(FiemapStatus::ErrorCode::NO_SPACE),
    };
    ErrorCode error_code() const { return error_code_; }
    bool is_ok() const { return error_code() == ErrorCode::SUCCESS; }
    operator bool() const { return is_ok(); }
    // Total required size on /userdata.
    uint64_t required_size() const { return required_size_; }
    std::string string() const;

    static Return Ok() { return Return(ErrorCode::SUCCESS); }
    static Return Error() { return Return(ErrorCode::ERROR); }
    static Return NoSpace(uint64_t size) { return Return(ErrorCode::NO_SPACE, size); }
    // Does not set required_size_ properly even when status.error_code() == NO_SPACE.
    explicit Return(const FiemapStatus& status)
        : error_code_(FromFiemapStatusErrorCode(status.error_code())), required_size_(0) {}

  private:
    ErrorCode error_code_;
    uint64_t required_size_;
    Return(ErrorCode error_code, uint64_t required_size = 0)
        : error_code_(error_code), required_size_(required_size) {}

    // FiemapStatus::ErrorCode -> ErrorCode
    static ErrorCode FromFiemapStatusErrorCode(FiemapStatus::ErrorCode error_code);
};

}  // namespace android::snapshot

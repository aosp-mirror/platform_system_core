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

#include <errno.h>
#include <stdint.h>

#include <string>

namespace android::fiemap {

// Represent error status of libfiemap classes.
class FiemapStatus {
  public:
    enum class ErrorCode : int32_t {
        SUCCESS = 0,
        // Generic non-recoverable failure.
        ERROR = INT32_MIN,
        // Not enough space
        NO_SPACE = -ENOSPC,
    };

    // Create from a given errno (specified in errno,h)
    static FiemapStatus FromErrno(int error_num) { return FiemapStatus(CastErrorCode(-error_num)); }

    // Create from an integer error code that is expected to be an ErrorCode
    // value. If it isn't, Error() is returned.
    static FiemapStatus FromErrorCode(int32_t error_code) {
        return FiemapStatus(CastErrorCode(error_code));
    }

    // Generic error.
    static FiemapStatus Error() { return FiemapStatus(ErrorCode::ERROR); }

    // Success.
    static FiemapStatus Ok() { return FiemapStatus(ErrorCode::SUCCESS); }

    ErrorCode error_code() const { return error_code_; }
    bool is_ok() const { return error_code() == ErrorCode::SUCCESS; }
    operator bool() const { return is_ok(); }

    // For logging and debugging only.
    std::string string() const;

  protected:
    FiemapStatus(ErrorCode code) : error_code_(code) {}

  private:
    ErrorCode error_code_;

    static ErrorCode CastErrorCode(int error);
};

}  // namespace android::fiemap

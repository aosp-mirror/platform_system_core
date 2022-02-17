/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include "Errors.h"

// It would have been better if this file (ErrorsMacros.h) is entirely in utils/Errors.h. However
// that is infeasible as some (actually many) are using utils/Errors.h via the implicit include path
// `system/core/include` [1].  Since such users are not guaranteed to specify the dependency to
// libbase_headers, the following headers from libbase_headers can't be found.
// [1] build/soong/cc/config/global.go#commonGlobalIncludes
#include <android-base/errors.h>
#include <android-base/result.h>

#include <assert.h>

namespace android {

// StatusT is a wrapper class for status_t. Use this type instead of status_t when instantiating
// Result<T, E> and Error<E> template classes. This is required to distinguish status_t from
// other integer-based error code types like errno, and also to provide utility functions like
// print().
struct StatusT {
    StatusT() : val_(OK) {}
    StatusT(status_t s) : val_(s) {}
    const status_t& value() const { return val_; }
    operator status_t() const { return val_; }
    std::string print() const { return statusToString(val_); }

    status_t val_;
};

namespace base {

// Specialization of android::base::OkOrFail<V> for V = status_t. This is used to use the OR_RETURN
// and OR_FATAL macros with statements that yields a value of status_t. See android-base/errors.h
// for the detailed contract.
template <>
struct OkOrFail<status_t> {
    // Tests if status_t is a success value of not.
    static bool IsOk(const status_t& s) { return s == OK; }

    // Unwrapping status_t in the success case is just asserting that it is actually a success.
    // We don't return OK because it would be redundant.
    static void Unwrap([[maybe_unused]] status_t&& s) { assert(IsOk(s)); }

    // Consumes status_t when it's a fail value
    static OkOrFail<status_t> Fail(status_t&& s) {
        assert(!IsOk(s));
        return OkOrFail<status_t>{s};
    }
    status_t val_;

    // And converts back into status_t. This is used when OR_RETURN is used in a function whose
    // return type is status_t.
    operator status_t() && { return val_; }

    // Or converts into Result<T, StatusT>. This is used when OR_RETURN is used in a function whose
    // return type is Result<T, StatusT>.
    template <typename T, typename = std::enable_if_t<!std::is_same_v<T, status_t>>>
    operator Result<T, StatusT>() && {
        return Error<StatusT>(std::move(val_));
    }

    operator Result<int, StatusT>() && { return Error<StatusT>(std::move(val_)); }

    // String representation of the error value.
    static std::string ErrorMessage(const status_t& s) { return statusToString(s); }
};

}  // namespace base
}  // namespace android

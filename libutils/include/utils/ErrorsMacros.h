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
#include <log/log_main.h>

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
// TODO(b/221235365) StatusT fulfill ResultError contract and cleanup.

// Unlike typical ResultError types, the underlying code should be a status_t
// instead of a StatusT. We also special-case message generation.
template<>
struct ResultError<StatusT, false> {
    ResultError(status_t s) : val_(s) {
        LOG_FATAL_IF(s == OK, "Result error should not hold success");
    }

    template <typename T>
    operator expected<T, ResultError<StatusT, false>>() const {
        return unexpected(*this);
    }

    std::string message() const { return statusToString(val_); }
    status_t code() const { return val_; }

 private:
    const status_t val_;
};

template<>
struct ResultError<StatusT, true> {
    template <typename T>
    ResultError(T&& message, status_t s) : val_(s), message_(std::forward<T>(message)) {
        LOG_FATAL_IF(s == OK, "Result error should not hold success");
    }

    ResultError(status_t s) : val_(s) {}

    template <typename T>
    operator expected<T, ResultError<StatusT, true>>() const {
        return unexpected(*this);
    }

    status_t code() const { return val_; }

    std::string message() const { return statusToString(val_) + message_; }
 private:
    const status_t val_;
    std::string message_;
};

// Specialization of android::base::OkOrFail<V> for V = status_t. This is used to use the OR_RETURN
// and OR_FATAL macros with statements that yields a value of status_t. See android-base/errors.h
// for the detailed contract.
template <>
struct OkOrFail<status_t> {
    static_assert(std::is_same_v<status_t, int>);
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

    template <typename T>
    operator Result<T, StatusT>() && {
        return ResultError<StatusT>(std::move(val_));
    }

    template<typename T>
    operator Result<T, StatusT, false>() && {
        return ResultError<StatusT, false>(std::move(val_));
    }

    // Since user defined conversion can be followed by numeric conversion,
    // we have to specialize all conversions to results holding numeric types to
    // avoid conversion ambiguities with the constructor of expected.
#pragma push_macro("SPECIALIZED_CONVERSION")
#define SPECIALIZED_CONVERSION(type)\
  operator Result<type, StatusT>() && { return ResultError<StatusT>(std::move(val_)); }\
  operator Result<type, StatusT, false>() && { return ResultError<StatusT, false>(std::move(val_));}

    SPECIALIZED_CONVERSION(int)
    SPECIALIZED_CONVERSION(short int)
    SPECIALIZED_CONVERSION(unsigned short int)
    SPECIALIZED_CONVERSION(unsigned int)
    SPECIALIZED_CONVERSION(long int)
    SPECIALIZED_CONVERSION(unsigned long int)
    SPECIALIZED_CONVERSION(long long int)
    SPECIALIZED_CONVERSION(unsigned long long int)
    SPECIALIZED_CONVERSION(bool)
    SPECIALIZED_CONVERSION(char)
    SPECIALIZED_CONVERSION(unsigned char)
    SPECIALIZED_CONVERSION(signed char)
    SPECIALIZED_CONVERSION(wchar_t)
    SPECIALIZED_CONVERSION(char16_t)
    SPECIALIZED_CONVERSION(char32_t)
    SPECIALIZED_CONVERSION(float)
    SPECIALIZED_CONVERSION(double)
    SPECIALIZED_CONVERSION(long double)
#undef SPECIALIZED_CONVERSION
#pragma pop_macro("SPECIALIZED_CONVERSION")
    // String representation of the error value.
    static std::string ErrorMessage(const status_t& s) { return statusToString(s); }
};
}  // namespace base


// These conversions make StatusT directly comparable to status_t in order to
// avoid calling code whenever comparisons are desired.

template <bool include_message>
bool operator==(const base::ResultError<StatusT, include_message>& l, const status_t& r) {
    return (l.code() == r);
}
template <bool include_message>
bool operator==(const status_t& l, const base::ResultError<StatusT, include_message>& r) {
    return (l == r.code());
}

template <bool include_message>
bool operator!=(const base::ResultError<StatusT, include_message>& l, const status_t& r) {
    return (l.code() != r);
}
template <bool include_message>
bool operator!=(const status_t& l, const base::ResultError<StatusT, include_message>& r) {
    return (l != r.code());
}

}  // namespace android

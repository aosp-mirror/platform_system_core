// Copyright (C) 2024 The Android Open Source Project
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

/* As a vendor default header included in all vendor modules, this header MUST NOT include other
 * header files or any declarations. Only macros are allowed.
 */
#if defined(__ANDROID_VENDOR__)

// LLNDK (https://source.android.com/docs/core/architecture/vndk/build-system#ll-ndk) is similar to
// NDK, but uses its own versioning of YYYYMM format for vendor builds. The LLNDK symbols are
// enabled when the vendor api level is equal to or newer than the ro.board.api_level.
#define __INTRODUCED_IN_LLNDK(vendor_api_level)                                             \
    _Pragma("clang diagnostic push") _Pragma("clang diagnostic ignored \"-Wgcc-compat\"")   \
            __attribute__((enable_if(                                                       \
                    __ANDROID_VENDOR_API__ >= vendor_api_level,                             \
                    "available in vendor API level " #vendor_api_level " that "             \
                    "is newer than the current vendor API level. Guard the API "            \
                    "call with '#if (__ANDROID_VENDOR_API__ >= " #vendor_api_level ")'."))) \
            _Pragma("clang diagnostic pop")

// Use this macro as an `if` statement to call an API that are available to both NDK and LLNDK.
// This returns true for the vendor modules if the vendor_api_level is less than or equal to the
// ro.board.api_level.
#define API_LEVEL_AT_LEAST(sdk_api_level, vendor_api_level) \
    constexpr(__ANDROID_VENDOR_API__ >= vendor_api_level)

#else  // __ANDROID_VENDOR__

// __INTRODUCED_IN_LLNDK is for LLNDK only but not for NDK. Ignore this for non-vendor modules.
// It leaves a no-op annotation for ABI analysis.
#if !defined(__INTRODUCED_IN_LLNDK)
#define __INTRODUCED_IN_LLNDK(vendor_api_level) \
    __attribute__((annotate("introduced_in_llndk=" #vendor_api_level)))
#endif

// For non-vendor modules, API_LEVEL_AT_LEAST is replaced with __builtin_available(sdk_api_level) to
// guard the API for __INTRODUCED_IN.
#if !defined(API_LEVEL_AT_LEAST)
#define API_LEVEL_AT_LEAST(sdk_api_level, vendor_api_level) \
    (__builtin_available(android sdk_api_level, *))
#endif

#endif  // __ANDROID_VENDOR__

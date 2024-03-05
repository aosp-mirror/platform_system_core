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

#include <sys/cdefs.h>

__BEGIN_DECLS

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

// For the vendor libraries, __INTRODUCED_IN must be ignored because they are only for NDKs but not
// for LLNDKs.
#undef __INTRODUCED_IN
#define __INTRODUCED_IN(x)

#else  // __ANDROID_VENDOR__

// For non-vendor libraries, __INTRODUCED_IN_LLNDK must be ignored because it must not change
// symbols of NDK or the system side of the treble boundary. It leaves a no-op annotation for ABI
// analysis.
#define __INTRODUCED_IN_LLNDK(vendor_api_level) \
    __attribute__((annotate("introduced_in_llndk=" #vendor_api_level)))

#endif  // __ANDROID_VENDOR__

__END_DECLS

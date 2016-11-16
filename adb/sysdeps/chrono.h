/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include <chrono>

#if defined(_WIN32)
// We don't have C++14 on Windows yet.
// Reimplement std::chrono_literals ourselves until we do.

// Silence the following warning (which gets promoted to an error):
// error: literal operator suffixes not preceded by ‘_’ are reserved for future standardization
#pragma GCC system_header

constexpr std::chrono::seconds operator"" s(unsigned long long s) {
    return std::chrono::seconds(s);
}

constexpr std::chrono::duration<long double> operator"" s(long double s) {
    return std::chrono::duration<long double>(s);
}

constexpr std::chrono::milliseconds operator"" ms(unsigned long long ms) {
    return std::chrono::milliseconds(ms);
}

constexpr std::chrono::duration<long double, std::milli> operator"" ms(long double ms) {
    return std::chrono::duration<long double, std::milli>(ms);
}
#else
using namespace std::chrono_literals;
#endif

#pragma once

/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include <memory>
#include <type_traits>

#if defined(_WIN32)
// We don't have C++14 on Windows yet.
// Reimplement std::make_unique ourselves until we do.

namespace internal {

template <typename T>
struct array_known_bounds;

template <typename T>
struct array_known_bounds<T[]> {
    constexpr static bool value = false;
};

template <typename T, size_t N>
struct array_known_bounds<T[N]> {
    constexpr static bool value = true;
};

}  // namespace internal

namespace std {

template <typename T, typename... Args>
typename std::enable_if<!std::is_array<T>::value, std::unique_ptr<T>>::type make_unique(
    Args&&... args) {
    return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
}

template <typename T>
typename std::enable_if<std::is_array<T>::value && !internal::array_known_bounds<T>::value,
                        std::unique_ptr<T>>::type
make_unique(std::size_t size) {
    return std::unique_ptr<T>(new typename std::remove_extent<T>::type[size]());
}

template <typename T, typename... Args>
typename std::enable_if<std::is_array<T>::value && internal::array_known_bounds<T>::value,
                        std::unique_ptr<T>>::type
make_unique(Args&&... args) = delete;

}  // namespace std

#endif

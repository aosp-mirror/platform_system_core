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

#ifndef LIBMEMUNREACHABLE_LEAK_H_
#define LIBMEMUNREACHABLE_LEAK_H_

#include <functional>
#include <vector>

#include "memunreachable/memunreachable.h"

// Custom std::hash specialization so that Leak::Backtrace can be used
// as a key in std::unordered_map.
namespace std {

template <>
struct hash<android::Leak::Backtrace> {
  std::size_t operator()(const android::Leak::Backtrace& key) const {
    std::size_t seed = 0;

    hash_combine(seed, key.num_frames);
    for (size_t i = 0; i < key.num_frames; i++) {
      hash_combine(seed, key.frames[i]);
    }

    return seed;
  }

 private:
  template <typename T>
  inline void hash_combine(std::size_t& seed, const T& v) const {
    std::hash<T> hasher;
    seed ^= hasher(v) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
  }
};

}  // namespace std

namespace android {

static bool operator==(const Leak::Backtrace& lhs, const Leak::Backtrace& rhs) {
  return (lhs.num_frames == rhs.num_frames) &&
         memcmp(lhs.frames, rhs.frames, lhs.num_frames * sizeof(lhs.frames[0])) == 0;
}
}

#endif

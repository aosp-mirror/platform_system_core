/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <stddef.h>
#include <stdint.h>

namespace adb {
namespace pairing {

template <size_t N>
class Counter {
  public:
    void Increase() {
        for (size_t i = sizeof(counter_) - 1; i < sizeof(counter_); --i) {
            if (++counter_[i] != 0) {
                break;
            }
        }
    }

    uint8_t* data() { return counter_; }
    const uint8_t* data() const { return counter_; }

    constexpr size_t size() const { return sizeof(counter_); }

    uint8_t& operator[](size_t index) { return counter_[index]; }
    const uint8_t& operator[](size_t index) const { return counter_[index]; }

  private:
    uint8_t counter_[N];
};

}  // namespace pairing
}  // namespace adb

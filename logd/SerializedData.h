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

#include <sys/types.h>

#include <algorithm>
#include <memory>

// This class is used instead of std::string or std::vector because their clear(), erase(), etc
// functions don't actually deallocate.  shrink_to_fit() does deallocate but is not guaranteed to
// work and swapping with an empty string/vector is clunky.
class SerializedData {
  public:
    SerializedData() {}
    SerializedData(size_t size) : data_(new uint8_t[size]), size_(size) {}

    void Resize(size_t new_size) {
        if (size_ == 0) {
            data_.reset(new uint8_t[new_size]);
            size_ = new_size;
        } else if (new_size == 0) {
            data_.reset();
            size_ = 0;
        } else if (new_size != size_) {
            std::unique_ptr<uint8_t[]> new_data(new uint8_t[new_size]);
            size_t copy_size = std::min(size_, new_size);
            memcpy(new_data.get(), data_.get(), copy_size);
            data_.swap(new_data);
            size_ = new_size;
        }
    }

    uint8_t* data() { return data_.get(); }
    const uint8_t* data() const { return data_.get(); }
    size_t size() const { return size_; }

  private:
    std::unique_ptr<uint8_t[]> data_;
    size_t size_ = 0;
};
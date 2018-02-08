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

#include <string>

#include <android-base/logging.h>

struct Range {
    explicit Range(std::string data) : data_(std::move(data)) {}

    Range(const Range& copy) = delete;
    Range& operator=(const Range& copy) = delete;

    Range(Range&& move) = default;
    Range& operator=(Range&& move) = default;

    bool empty() const {
        return size() == 0;
    }

    size_t size() const {
        return data_.size() - begin_offset_ - end_offset_;
    };

    void drop_front(size_t n) {
        CHECK_GE(size(), n);
        begin_offset_ += n;
    }

    void drop_end(size_t n) {
        CHECK_GE(size(), n);
        end_offset_ += n;
    }

    char* data() {
        return &data_[0] + begin_offset_;
    }

    std::string::iterator begin() {
        return data_.begin() + begin_offset_;
    }

    std::string::iterator end() {
        return data_.end() - end_offset_;
    }

    std::string data_;
    size_t begin_offset_ = 0;
    size_t end_offset_ = 0;
};

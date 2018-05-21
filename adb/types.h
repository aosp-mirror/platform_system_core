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

#pragma once

#include <algorithm>
#include <utility>

#include <android-base/logging.h>

#include "sysdeps/memory.h"

// Essentially std::vector<char>, except without zero initialization or reallocation.
struct Block {
    using iterator = char*;

    Block() {}

    explicit Block(size_t size) { allocate(size); }

    template <typename Iterator>
    Block(Iterator begin, Iterator end) : Block(end - begin) {
        std::copy(begin, end, data_);
    }

    Block(const Block& copy) = delete;
    Block(Block&& move) {
        std::swap(data_, move.data_);
        std::swap(capacity_, move.capacity_);
        std::swap(size_, move.size_);
    }

    Block& operator=(const Block& copy) = delete;
    Block& operator=(Block&& move) {
        clear();

        std::swap(data_, move.data_);
        std::swap(capacity_, move.capacity_);
        std::swap(size_, move.size_);

        return *this;
    }

    ~Block() { clear(); }

    void resize(size_t new_size) {
        if (!data_) {
            allocate(new_size);
        } else {
            CHECK_GE(capacity_, new_size);
            size_ = new_size;
        }
    }

    template <typename InputIt>
    void assign(InputIt begin, InputIt end) {
        clear();
        allocate(end - begin);
        std::copy(begin, end, data_);
    }

    void clear() {
        free(data_);
        capacity_ = 0;
        size_ = 0;
    }

    size_t capacity() const { return capacity_; }
    size_t size() const { return size_; }
    bool empty() const { return size() == 0; }

    char* data() { return data_; }
    const char* data() const { return data_; }

    char* begin() { return data_; }
    const char* begin() const { return data_; }

    char* end() { return data() + size_; }
    const char* end() const { return data() + size_; }

    char& operator[](size_t idx) { return data()[idx]; }
    const char& operator[](size_t idx) const { return data()[idx]; }

    bool operator==(const Block& rhs) const {
        return size() == rhs.size() && memcmp(data(), rhs.data(), size()) == 0;
    }

  private:
    void allocate(size_t size) {
        CHECK(data_ == nullptr);
        CHECK_EQ(0ULL, capacity_);
        CHECK_EQ(0ULL, size_);
        if (size != 0) {
            data_ = static_cast<char*>(malloc(size));
            capacity_ = size;
            size_ = size;
        }
    }

    char* data_ = nullptr;
    size_t capacity_ = 0;
    size_t size_ = 0;
};

struct amessage {
    uint32_t command;     /* command identifier constant      */
    uint32_t arg0;        /* first argument                   */
    uint32_t arg1;        /* second argument                  */
    uint32_t data_length; /* length of payload (0 is allowed) */
    uint32_t data_check;  /* checksum of data payload         */
    uint32_t magic;       /* command ^ 0xffffffff             */
};

struct apacket {
    using payload_type = Block;
    amessage msg;
    payload_type payload;
};

struct Range {
    explicit Range(apacket::payload_type data) : data_(std::move(data)) {}

    Range(const Range& copy) = delete;
    Range& operator=(const Range& copy) = delete;

    Range(Range&& move) = default;
    Range& operator=(Range&& move) = default;

    size_t size() const { return data_.size() - begin_offset_ - end_offset_; };
    bool empty() const { return size() == 0; }

    void drop_front(size_t n) {
        CHECK_GE(size(), n);
        begin_offset_ += n;
    }

    void drop_end(size_t n) {
        CHECK_GE(size(), n);
        end_offset_ += n;
    }

    char* data() { return &data_[0] + begin_offset_; }

    apacket::payload_type::iterator begin() { return data_.begin() + begin_offset_; }
    apacket::payload_type::iterator end() { return data_.end() - end_offset_; }

    apacket::payload_type data_;
    size_t begin_offset_ = 0;
    size_t end_offset_ = 0;
};

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
#include <deque>
#include <memory>
#include <type_traits>
#include <utility>
#include <vector>

#include <android-base/logging.h>

#include "sysdeps/uio.h"

// Essentially std::vector<char>, except without zero initialization or reallocation.
struct Block {
    using iterator = char*;

    Block() {}

    explicit Block(size_t size) { allocate(size); }

    template <typename Iterator>
    Block(Iterator begin, Iterator end) : Block(end - begin) {
        std::copy(begin, end, data_.get());
    }

    Block(const Block& copy) = delete;
    Block(Block&& move) noexcept {
        std::swap(data_, move.data_);
        std::swap(capacity_, move.capacity_);
        std::swap(size_, move.size_);
    }

    Block& operator=(const Block& copy) = delete;
    Block& operator=(Block&& move) noexcept {
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
        std::copy(begin, end, data_.get());
    }

    void clear() {
        data_.reset();
        capacity_ = 0;
        size_ = 0;
    }

    size_t capacity() const { return capacity_; }
    size_t size() const { return size_; }
    bool empty() const { return size() == 0; }

    char* data() { return data_.get(); }
    const char* data() const { return data_.get(); }

    char* begin() { return data_.get(); }
    const char* begin() const { return data_.get(); }

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
            // This isn't std::make_unique because that's equivalent to `new char[size]()`, which
            // value-initializes the array instead of leaving it uninitialized. As an optimization,
            // call new without parentheses to avoid this costly initialization.
            data_.reset(new char[size]);
            capacity_ = size;
            size_ = size;
        }
    }

    std::unique_ptr<char[]> data_;
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

struct IOVector {
    using value_type = char;
    using block_type = Block;
    using size_type = size_t;

    IOVector() {}

    explicit IOVector(std::unique_ptr<block_type> block) {
        append(std::move(block));
    }

    IOVector(const IOVector& copy) = delete;
    IOVector(IOVector&& move) noexcept : IOVector() { *this = std::move(move); }

    IOVector& operator=(const IOVector& copy) = delete;
    IOVector& operator=(IOVector&& move) noexcept {
        chain_ = std::move(move.chain_);
        chain_length_ = move.chain_length_;
        begin_offset_ = move.begin_offset_;
        end_offset_ = move.end_offset_;

        move.chain_.clear();
        move.chain_length_ = 0;
        move.begin_offset_ = 0;
        move.end_offset_ = 0;

        return *this;
    }

    size_type size() const { return chain_length_ - begin_offset_ - end_offset_; }
    bool empty() const { return size() == 0; }

    void clear() {
        chain_length_ = 0;
        begin_offset_ = 0;
        end_offset_ = 0;
        chain_.clear();
    }

    // Split the first |len| bytes out of this chain into its own.
    IOVector take_front(size_type len) {
        IOVector head;

        if (len == 0) {
            return head;
        }
        CHECK_GE(size(), len);

        std::shared_ptr<const block_type> first_block = chain_.front();
        CHECK_GE(first_block->size(), begin_offset_);
        head.append_shared(std::move(first_block));
        head.begin_offset_ = begin_offset_;

        while (head.size() < len) {
            pop_front_block();
            CHECK(!chain_.empty());

            head.append_shared(chain_.front());
        }

        if (head.size() == len) {
            // Head takes full ownership of the last block it took.
            head.end_offset_ = 0;
            begin_offset_ = 0;
            pop_front_block();
        } else {
            // Head takes partial ownership of the last block it took.
            size_t bytes_taken = head.size() - len;
            head.end_offset_ = bytes_taken;
            CHECK_GE(chain_.front()->size(), bytes_taken);
            begin_offset_ = chain_.front()->size() - bytes_taken;
        }

        return head;
    }

    // Add a nonempty block to the chain.
    // The end of the chain must be a complete block (i.e. end_offset_ == 0).
    void append(std::unique_ptr<const block_type> block) {
        if (block->size() == 0) {
            return;
        }

        CHECK_EQ(0ULL, end_offset_);
        chain_length_ += block->size();
        chain_.emplace_back(std::move(block));
    }

    void append(block_type&& block) { append(std::make_unique<block_type>(std::move(block))); }

    void trim_front() {
        if (begin_offset_ == 0) {
            return;
        }

        const block_type* first_block = chain_.front().get();
        auto copy = std::make_unique<block_type>(first_block->size() - begin_offset_);
        memcpy(copy->data(), first_block->data() + begin_offset_, copy->size());
        chain_.front() = std::move(copy);

        chain_length_ -= begin_offset_;
        begin_offset_ = 0;
    }

  private:
    // append, except takes a shared_ptr.
    // Private to prevent exterior mutation of blocks.
    void append_shared(std::shared_ptr<const block_type> block) {
        CHECK_NE(0ULL, block->size());
        CHECK_EQ(0ULL, end_offset_);
        chain_length_ += block->size();
        chain_.emplace_back(std::move(block));
    }

    // Drop the front block from the chain, and update chain_length_ appropriately.
    void pop_front_block() {
        chain_length_ -= chain_.front()->size();
        begin_offset_ = 0;
        chain_.pop_front();
    }

    // Iterate over the blocks with a callback with an operator()(const char*, size_t).
    template <typename Fn>
    void iterate_blocks(Fn&& callback) const {
        if (chain_.size() == 0) {
            return;
        }

        for (size_t i = 0; i < chain_.size(); ++i) {
            const std::shared_ptr<const block_type>& block = chain_.at(i);
            const char* begin = block->data();
            size_t length = block->size();

            // Note that both of these conditions can be true if there's only one block.
            if (i == 0) {
                CHECK_GE(block->size(), begin_offset_);
                begin += begin_offset_;
                length -= begin_offset_;
            }

            if (i == chain_.size() - 1) {
                CHECK_GE(length, end_offset_);
                length -= end_offset_;
            }

            callback(begin, length);
        }
    }

  public:
    // Copy all of the blocks into a single block.
    template <typename CollectionType = block_type>
    CollectionType coalesce() const {
        CollectionType result;
        if (size() == 0) {
            return result;
        }

        result.resize(size());

        size_t offset = 0;
        iterate_blocks([&offset, &result](const char* data, size_t len) {
            memcpy(&result[offset], data, len);
            offset += len;
        });

        return result;
    }

    template <typename FunctionType>
    auto coalesced(FunctionType&& f) const ->
        typename std::result_of<FunctionType(const char*, size_t)>::type {
        if (chain_.size() == 1) {
            // If we only have one block, we can use it directly.
            return f(chain_.front()->data() + begin_offset_, size());
        } else {
            // Otherwise, copy to a single block.
            auto data = coalesce();
            return f(data.data(), data.size());
        }
    }

    // Get a list of iovecs that can be used to write out all of the blocks.
    std::vector<adb_iovec> iovecs() const {
        std::vector<adb_iovec> result;
        iterate_blocks([&result](const char* data, size_t len) {
            adb_iovec iov;
            iov.iov_base = const_cast<char*>(data);
            iov.iov_len = len;
            result.emplace_back(iov);
        });

        return result;
    }

  private:
    // Total length of all of the blocks in the chain.
    size_t chain_length_ = 0;

    size_t begin_offset_ = 0;
    size_t end_offset_ = 0;
    std::deque<std::shared_ptr<const block_type>> chain_;
};

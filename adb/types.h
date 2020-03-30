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

#include <string.h>

#include <algorithm>
#include <memory>
#include <utility>
#include <vector>

#include <android-base/logging.h>

#include "fdevent/fdevent.h"
#include "sysdeps/uio.h"

// Essentially std::vector<char>, except without zero initialization or reallocation.
struct Block {
    using iterator = char*;

    Block() = default;

    explicit Block(size_t size) { allocate(size); }

    template <typename Iterator>
    Block(Iterator begin, Iterator end) : Block(end - begin) {
        std::copy(begin, end, data_.get());
    }

    Block(const Block& copy) = delete;
    Block(Block&& move) noexcept
        : data_(std::exchange(move.data_, nullptr)),
          capacity_(std::exchange(move.capacity_, 0)),
          size_(std::exchange(move.size_, 0)) {}

    Block& operator=(const Block& copy) = delete;
    Block& operator=(Block&& move) noexcept {
        clear();
        data_ = std::exchange(move.data_, nullptr);
        capacity_ = std::exchange(move.capacity_, 0);
        size_ = std::exchange(move.size_, 0);
        return *this;
    }

    ~Block() = default;

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

    IOVector() = default;

    explicit IOVector(block_type&& block) { append(std::move(block)); }

    IOVector(const IOVector& copy) = delete;
    IOVector(IOVector&& move) noexcept : IOVector() { *this = std::move(move); }

    IOVector& operator=(const IOVector& copy) = delete;
    IOVector& operator=(IOVector&& move) noexcept;

    const value_type* front_data() const {
        if (chain_.empty()) {
            return nullptr;
        }

        return chain_.front().data() + begin_offset_;
    }

    size_type front_size() const {
        if (chain_.empty()) {
            return 0;
        }

        return chain_.front().size() - begin_offset_;
    }

    size_type size() const { return chain_length_ - begin_offset_; }
    bool empty() const { return size() == 0; }

    // Return the last block so the caller can still reuse its allocated capacity
    // or it can be simply ignored.
    block_type clear();

    void drop_front(size_type len);

    // Split the first |len| bytes out of this chain into its own.
    IOVector take_front(size_type len);

    // Add a nonempty block to the chain.
    void append(block_type&& block) {
        if (block.size() == 0) {
            return;
        }
        CHECK_NE(0ULL, block.size());
        chain_length_ += block.size();
        chain_.emplace_back(std::move(block));
    }

    void trim_front();

  private:
    void trim_chain_front();

    // Drop the front block from the chain, and update chain_length_ appropriately.
    void pop_front_block();

    // Iterate over the blocks with a callback with an operator()(const char*, size_t).
    template <typename Fn>
    void iterate_blocks(Fn&& callback) const {
        if (size() == 0) {
            return;
        }

        for (size_t i = start_index_; i < chain_.size(); ++i) {
            const auto& block = chain_[i];
            const char* begin = block.data();
            size_t length = block.size();

            if (i == start_index_) {
                CHECK_GE(block.size(), begin_offset_);
                begin += begin_offset_;
                length -= begin_offset_;
            }
            callback(begin, length);
        }
    }

  public:
    // Copy all of the blocks into a single block.
    template <typename CollectionType = block_type>
    CollectionType coalesce() const& {
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

    block_type coalesce() &&;

    template <typename FunctionType>
    auto coalesced(FunctionType&& f) const {
        if (chain_.size() == start_index_ + 1) {
            // If we only have one block, we can use it directly.
            return f(chain_[start_index_].data() + begin_offset_, size());
        } else {
            // Otherwise, copy to a single block.
            auto data = coalesce();
            return f(data.data(), data.size());
        }
    }

    // Get a list of iovecs that can be used to write out all of the blocks.
    std::vector<adb_iovec> iovecs() const;

  private:
    // Total length of all of the blocks in the chain.
    size_t chain_length_ = 0;

    size_t begin_offset_ = 0;
    size_t start_index_ = 0;
    std::vector<block_type> chain_;
};

// An implementation of weak pointers tied to the fdevent run loop.
//
// This allows for code to submit a request for an object, and upon receiving
// a response, know whether the object is still alive, or has been destroyed
// because of other reasons. We keep a list of living weak_ptrs in each object,
// and clear the weak_ptrs when the object is destroyed. This is safe, because
// we require that both the destructor of the referent and the get method on
// the weak_ptr are executed on the main thread.
template <typename T>
struct enable_weak_from_this;

template <typename T>
struct weak_ptr {
    weak_ptr() = default;
    explicit weak_ptr(T* ptr) { reset(ptr); }
    weak_ptr(const weak_ptr& copy) { reset(copy.get()); }

    weak_ptr(weak_ptr&& move) {
        reset(move.get());
        move.reset();
    }

    ~weak_ptr() { reset(); }

    weak_ptr& operator=(const weak_ptr& copy) {
        if (&copy == this) {
            return *this;
        }

        reset(copy.get());
        return *this;
    }

    weak_ptr& operator=(weak_ptr&& move) {
        if (&move == this) {
            return *this;
        }

        reset(move.get());
        move.reset();
        return *this;
    }

    T* get() {
        check_main_thread();
        return ptr_;
    }

    void reset(T* ptr = nullptr) {
        check_main_thread();

        if (ptr == ptr_) {
            return;
        }

        if (ptr_) {
            ptr_->weak_ptrs_.erase(
                    std::remove(ptr_->weak_ptrs_.begin(), ptr_->weak_ptrs_.end(), this));
        }

        ptr_ = ptr;
        if (ptr_) {
            ptr_->weak_ptrs_.push_back(this);
        }
    }

  private:
    friend struct enable_weak_from_this<T>;
    T* ptr_ = nullptr;
};

template <typename T>
struct enable_weak_from_this {
    ~enable_weak_from_this() {
        if (!weak_ptrs_.empty()) {
            check_main_thread();
            for (auto& weak : weak_ptrs_) {
                weak->ptr_ = nullptr;
            }
            weak_ptrs_.clear();
        }
    }

    weak_ptr<T> weak() { return weak_ptr<T>(static_cast<T*>(this)); }

    void schedule_deletion() {
        fdevent_run_on_main_thread([this]() { delete this; });
    }

  private:
    friend struct weak_ptr<T>;
    std::vector<weak_ptr<T>*> weak_ptrs_;
};

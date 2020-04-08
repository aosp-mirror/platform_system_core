/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include "types.h"

IOVector& IOVector::operator=(IOVector&& move) noexcept {
    chain_ = std::move(move.chain_);
    chain_length_ = move.chain_length_;
    begin_offset_ = move.begin_offset_;
    start_index_ = move.start_index_;

    move.clear();
    return *this;
}

IOVector::block_type IOVector::clear() {
    chain_length_ = 0;
    begin_offset_ = 0;
    start_index_ = 0;
    block_type res;
    if (!chain_.empty()) {
        res = std::move(chain_.back());
    }
    chain_.clear();
    return res;
}

void IOVector::drop_front(IOVector::size_type len) {
    if (len == 0) {
        return;
    }
    if (len == size()) {
        clear();
        return;
    }
    CHECK_LT(len, size());

    auto dropped = 0u;
    while (dropped < len) {
        const auto next = chain_[start_index_].size() - begin_offset_;
        if (dropped + next <= len) {
            pop_front_block();
            dropped += next;
        } else {
            const auto taken = len - dropped;
            begin_offset_ += taken;
            break;
        }
    }
}

IOVector IOVector::take_front(IOVector::size_type len) {
    if (len == 0) {
        return {};
    }
    if (len == size()) {
        return std::move(*this);
    }

    CHECK_GE(size(), len);
    IOVector res;
    // first iterate over the blocks that completely go into the other vector
    while (chain_[start_index_].size() - begin_offset_ <= len) {
        chain_length_ -= chain_[start_index_].size();
        len -= chain_[start_index_].size() - begin_offset_;
        if (chain_[start_index_].size() > begin_offset_) {
            res.append(std::move(chain_[start_index_]));
            if (begin_offset_) {
                res.begin_offset_ = std::exchange(begin_offset_, 0);
            }
        } else {
            begin_offset_ = 0;
        }
        ++start_index_;
    }

    if (len > 0) {
        // what's left is a single buffer that needs to be split between the |res| and |this|
        // we know that it has to be split - there was a check for the case when it has to
        // go away as a whole.
        if (begin_offset_ != 0 || len < chain_[start_index_].size() / 2) {
            // let's memcpy the data out
            block_type block(chain_[start_index_].begin() + begin_offset_,
                             chain_[start_index_].begin() + begin_offset_ + len);
            res.append(std::move(block));
            begin_offset_ += len;
        } else {
            CHECK_EQ(begin_offset_, 0u);
            // move out the internal buffer out and copy only the tail of it back in
            block_type block(chain_[start_index_].begin() + len, chain_[start_index_].end());
            chain_length_ -= chain_[start_index_].size();
            chain_[start_index_].resize(len);
            res.append(std::move(chain_[start_index_]));
            chain_length_ += block.size();
            chain_[start_index_] = std::move(block);
        }
    }
    return res;
}

void IOVector::trim_front() {
    if ((begin_offset_ == 0 && start_index_ == 0) || chain_.empty()) {
        return;
    }
    block_type& first_block = chain_[start_index_];
    if (begin_offset_ == first_block.size()) {
        ++start_index_;
    } else {
        memmove(first_block.data(), first_block.data() + begin_offset_,
                first_block.size() - begin_offset_);
        first_block.resize(first_block.size() - begin_offset_);
    }
    chain_length_ -= begin_offset_;
    begin_offset_ = 0;
    trim_chain_front();
}

void IOVector::trim_chain_front() {
    if (start_index_) {
        chain_.erase(chain_.begin(), chain_.begin() + start_index_);
        start_index_ = 0;
    }
}

void IOVector::pop_front_block() {
    chain_length_ -= chain_[start_index_].size();
    begin_offset_ = 0;
    chain_[start_index_].clear();
    ++start_index_;
    if (start_index_ > std::max<size_t>(4, chain_.size() / 2)) {
        trim_chain_front();
    }
}

IOVector::block_type IOVector::coalesce() && {
    // Destructive coalesce() may optimize for several cases when it doesn't need to allocate
    // new buffer, or even return one of the existing blocks as is. The only guarantee is that
    // after this call the IOVector is in some valid state. Nothing is guaranteed about the
    // specifics.
    if (size() == 0) {
        return {};
    }
    if (begin_offset_ == chain_[start_index_].size() && chain_.size() == start_index_ + 2) {
        chain_length_ -= chain_.back().size();
        auto res = std::move(chain_.back());
        chain_.pop_back();
        return res;
    }
    if (chain_.size() == start_index_ + 1) {
        chain_length_ -= chain_.back().size();
        auto res = std::move(chain_.back());
        chain_.pop_back();
        if (begin_offset_ != 0) {
            memmove(res.data(), res.data() + begin_offset_, res.size() - begin_offset_);
            res.resize(res.size() - begin_offset_);
            begin_offset_ = 0;
        }
        return res;
    }
    if (auto& firstBuffer = chain_[start_index_]; firstBuffer.capacity() >= size()) {
        auto res = std::move(chain_[start_index_]);
        auto size = res.size();
        chain_length_ -= size;
        if (begin_offset_ != 0) {
            memmove(res.data(), res.data() + begin_offset_, res.size() - begin_offset_);
            size -= begin_offset_;
            begin_offset_ = 0;
        }
        for (auto i = start_index_ + 1; i < chain_.size(); ++i) {
            memcpy(res.data() + size, chain_[i].data(), chain_[i].size());
            size += chain_[i].size();
        }
        res.resize(size);
        ++start_index_;
        return res;
    }
    return const_cast<const IOVector*>(this)->coalesce<>();
}

std::vector<adb_iovec> IOVector::iovecs() const {
    std::vector<adb_iovec> result;
    result.reserve(chain_.size() - start_index_);
    iterate_blocks([&result](const char* data, size_t len) {
        adb_iovec iov;
        iov.iov_base = const_cast<char*>(data);
        iov.iov_len = len;
        result.emplace_back(iov);
    });

    return result;
}

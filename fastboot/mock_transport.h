//
// Copyright (C) 2023 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#pragma once

#include <string.h>

#include <algorithm>
#include <string_view>

#include <gmock/gmock.h>
#include "transport.h"

class MockTransport : public Transport {
  public:
    MOCK_METHOD(ssize_t, Read, (void* data, size_t len), (override));
    MOCK_METHOD(ssize_t, Write, (const void* data, size_t len), (override));
    MOCK_METHOD(int, Close, (), (override));
    MOCK_METHOD(int, Reset, (), (override));
};

class RawDataMatcher {
  public:
    explicit RawDataMatcher(const char* data) : data_(data) {}
    explicit RawDataMatcher(std::string_view data) : data_(data) {}

    bool MatchAndExplain(std::tuple<const void*, size_t> args,
                         ::testing::MatchResultListener*) const {
        const void* expected_data = std::get<0>(args);
        size_t expected_len = std::get<1>(args);
        if (expected_len != data_.size()) {
            return false;
        }
        return memcmp(expected_data, data_.data(), expected_len) == 0;
    }
    void DescribeTo(std::ostream* os) const { *os << "raw data is"; }
    void DescribeNegationTo(std::ostream* os) const { *os << "raw data is not"; }

  private:
    std::string_view data_;
};

template <typename T>
static inline ::testing::PolymorphicMatcher<RawDataMatcher> RawData(T data) {
    return ::testing::MakePolymorphicMatcher(RawDataMatcher(data));
}

static inline auto CopyData(const char* source) {
    return [source](void* buffer, size_t size) -> ssize_t {
        size_t to_copy = std::min(size, strlen(source));
        memcpy(buffer, source, to_copy);
        return to_copy;
    };
};

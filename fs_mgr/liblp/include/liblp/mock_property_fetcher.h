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

#pragma once

#include <gmock/gmock.h>

#include <liblp/property_fetcher.h>

namespace android {
namespace fs_mgr {
namespace testing {

class MockPropertyFetcher : public IPropertyFetcher {
  public:
    MOCK_METHOD2(GetProperty, std::string(const std::string&, const std::string&));
    MOCK_METHOD2(GetBoolProperty, bool(const std::string&, bool));

    // By default, return default_value for all functions.
    MockPropertyFetcher() {
        using ::testing::_;
        using ::testing::Invoke;
        ON_CALL(*this, GetProperty(_, _)).WillByDefault(Invoke([](const auto&, const auto& def) {
            return def;
        }));
        ON_CALL(*this, GetBoolProperty(_, _)).WillByDefault(Invoke([](const auto&, auto def) {
            return def;
        }));
    }
};

static inline void ResetMockPropertyFetcher() {
    IPropertyFetcher::OverrideForTesting(
            std::make_unique<::testing::NiceMock<MockPropertyFetcher>>());
}

static inline MockPropertyFetcher* GetMockedPropertyFetcher() {
    return static_cast<MockPropertyFetcher*>(IPropertyFetcher::GetInstance());
}

}  // namespace testing
}  // namespace fs_mgr
}  // namespace android

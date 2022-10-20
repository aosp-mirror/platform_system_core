/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include "epoll.h"

#include <sys/unistd.h>

#include <unordered_set>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <gtest/gtest.h>

namespace android {
namespace init {

std::unordered_set<void*> sValidObjects;

class CatchDtor final {
  public:
    CatchDtor() { CHECK(sValidObjects.emplace(this).second); }
    CatchDtor(const CatchDtor&) { CHECK(sValidObjects.emplace(this).second); }
    CatchDtor(const CatchDtor&&) { CHECK(sValidObjects.emplace(this).second); }
    ~CatchDtor() { CHECK_EQ(sValidObjects.erase(this), size_t{1}); }
};

TEST(epoll, UnregisterHandler) {
    Epoll epoll;
    ASSERT_RESULT_OK(epoll.Open());

    int fds[2];
    ASSERT_EQ(pipe(fds), 0);

    CatchDtor catch_dtor;
    bool handler_invoked = false;
    auto handler = [&, catch_dtor]() -> void {
        auto result = epoll.UnregisterHandler(fds[0]);
        ASSERT_EQ(result.ok(), !handler_invoked);
        handler_invoked = true;
        // The assert statement below verifies that the UnregisterHandler() call
        // above did not destroy the current std::function<> instance.
        ASSERT_NE(sValidObjects.find((void*)&catch_dtor), sValidObjects.end());
    };

    epoll.RegisterHandler(fds[0], std::move(handler));

    uint8_t byte = 0xee;
    ASSERT_TRUE(android::base::WriteFully(fds[1], &byte, sizeof(byte)));

    auto results = epoll.Wait({});
    ASSERT_RESULT_OK(results);
    ASSERT_EQ(results->size(), size_t(1));

    for (const auto& function : *results) {
        (*function)();
        (*function)();
    }
    ASSERT_TRUE(handler_invoked);
}

}  // namespace init
}  // namespace android

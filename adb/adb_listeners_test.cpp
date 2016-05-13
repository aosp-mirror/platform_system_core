/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include "adb_listeners.h"

#include <gtest/gtest.h>

#include <android-base/stringprintf.h>
#include <android-base/strings.h>

#include "fdevent.h"
#include "sysdeps.h"
#include "transport.h"

// Returns true if the given listener is present in format_listeners(). Empty parameters will
// be ignored.
static bool listener_is_installed(const std::string& serial, const std::string& source,
                                  const std::string& dest) {
    // format_listeners() gives lines of "<serial> <source> <dest>\n".
    for (const std::string& line : android::base::Split(format_listeners(), "\n")) {
        std::vector<std::string> info = android::base::Split(line, " ");
        if (info.size() == 3 &&
                (serial.empty() || info[0] == serial) &&
                (source.empty() || info[1] == source) &&
                (dest.empty() || info[2] == dest)) {
            return true;
        }
    }

    return false;
}

class AdbListenersTest : public ::testing::Test {
  public:
    void SetUp() override {
        // We don't need an fdevent loop, but adding/removing listeners must be done from the
        // fdevent thread if one exists. Since previously run tests may have created an fdevent
        // thread, we need to reset to prevent the thread check.
        fdevent_reset();
    }

    void TearDown() override {
        // Clean up any listeners that may have been installed.
        remove_all_listeners();

        // Make sure we didn't leave any dangling events.
        ASSERT_EQ(0u, fdevent_installed_count());
    }

  protected:
    atransport transport_;
};

TEST_F(AdbListenersTest, test_install_listener) {
    std::string error;

    ASSERT_EQ(INSTALL_STATUS_OK,
              install_listener("tcp:9000", "tcp:9000", &transport_, false, nullptr, &error));
    ASSERT_TRUE(error.empty());

    ASSERT_TRUE(listener_is_installed("", "tcp:9000", "tcp:9000"));
}

TEST_F(AdbListenersTest, test_install_listener_rebind) {
    std::string error;

    ASSERT_EQ(INSTALL_STATUS_OK,
              install_listener("tcp:9000", "tcp:9000", &transport_, false, nullptr, &error));
    ASSERT_TRUE(error.empty());

    ASSERT_EQ(INSTALL_STATUS_OK,
              install_listener("tcp:9000", "tcp:9001", &transport_, false, nullptr, &error));
    ASSERT_TRUE(error.empty());

    ASSERT_TRUE(listener_is_installed("", "tcp:9000", "tcp:9001"));
}

TEST_F(AdbListenersTest, test_install_listener_no_rebind) {
    std::string error;

    ASSERT_EQ(INSTALL_STATUS_OK,
              install_listener("tcp:9000", "tcp:9000", &transport_, true, nullptr, &error));
    ASSERT_TRUE(error.empty());

    ASSERT_EQ(INSTALL_STATUS_CANNOT_REBIND,
              install_listener("tcp:9000", "tcp:9001", &transport_, true, nullptr, &error));
    ASSERT_FALSE(error.empty());

    ASSERT_TRUE(listener_is_installed("", "tcp:9000", "tcp:9000"));
}

TEST_F(AdbListenersTest, test_install_listener_tcp_port_0) {
    int port = 0;
    std::string error;

    ASSERT_EQ(INSTALL_STATUS_OK,
              install_listener("tcp:0", "tcp:9000", &transport_, true, &port, &error));
    ASSERT_TRUE(error.empty());

    ASSERT_TRUE(listener_is_installed("", android::base::StringPrintf("tcp:%d", port), "tcp:9000"));
}

TEST_F(AdbListenersTest, test_remove_listener) {
    std::string error;

    ASSERT_EQ(INSTALL_STATUS_OK,
              install_listener("tcp:9000", "tcp:9000", &transport_, false, nullptr, &error));
    ASSERT_TRUE(error.empty());

    ASSERT_EQ(INSTALL_STATUS_OK, remove_listener("tcp:9000", &transport_));
    ASSERT_TRUE(format_listeners().empty());
}

TEST_F(AdbListenersTest, test_remove_nonexistent_listener) {
    std::string error;

    ASSERT_EQ(INSTALL_STATUS_OK,
              install_listener("tcp:9000", "tcp:9000", &transport_, false, nullptr, &error));
    ASSERT_TRUE(error.empty());

    ASSERT_EQ(INSTALL_STATUS_LISTENER_NOT_FOUND, remove_listener("tcp:1", &transport_));
    ASSERT_TRUE(listener_is_installed("", "tcp:9000", "tcp:9000"));
}

TEST_F(AdbListenersTest, test_remove_all_listeners) {
    std::string error;

    ASSERT_EQ(INSTALL_STATUS_OK,
              install_listener("tcp:9000", "tcp:9000", &transport_, false, nullptr, &error));
    ASSERT_TRUE(error.empty());

    ASSERT_EQ(INSTALL_STATUS_OK,
              install_listener("tcp:9001", "tcp:9001", &transport_, false, nullptr, &error));
    ASSERT_TRUE(error.empty());

    remove_all_listeners();
    ASSERT_TRUE(format_listeners().empty());
}

TEST_F(AdbListenersTest, test_transport_disconnect) {
    std::string error;

    ASSERT_EQ(INSTALL_STATUS_OK,
              install_listener("tcp:9000", "tcp:9000", &transport_, false, nullptr, &error));
    ASSERT_TRUE(error.empty());

    ASSERT_EQ(INSTALL_STATUS_OK,
              install_listener("tcp:9001", "tcp:9001", &transport_, false, nullptr, &error));
    ASSERT_TRUE(error.empty());

    transport_.RunDisconnects();
    ASSERT_TRUE(format_listeners().empty());
}

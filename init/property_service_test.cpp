/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include <errno.h>
#include <sys/socket.h>
#include <sys/system_properties.h>
#include <sys/un.h>

#include <android-base/properties.h>
#include <android-base/scopeguard.h>
#include <android-base/strings.h>
#include <gtest/gtest.h>

using android::base::GetProperty;
using android::base::SetProperty;

namespace android {
namespace init {

TEST(property_service, very_long_name_35166374) {
  // Connect to the property service directly...
  int fd = socket(AF_LOCAL, SOCK_STREAM | SOCK_CLOEXEC, 0);
  ASSERT_NE(fd, -1);

  static const char* property_service_socket = "/dev/socket/" PROP_SERVICE_NAME;
  sockaddr_un addr = {};
  addr.sun_family = AF_LOCAL;
  strlcpy(addr.sun_path, property_service_socket, sizeof(addr.sun_path));

  socklen_t addr_len = strlen(property_service_socket) + offsetof(sockaddr_un, sun_path) + 1;
  ASSERT_NE(connect(fd, reinterpret_cast<sockaddr*>(&addr), addr_len), -1);

  // ...so we can send it a malformed request.
  uint32_t msg = PROP_MSG_SETPROP2;
  uint32_t size = 0xffffffff;

  ASSERT_EQ(static_cast<ssize_t>(sizeof(msg)), send(fd, &msg, sizeof(msg), 0));
  ASSERT_EQ(static_cast<ssize_t>(sizeof(size)), send(fd, &size, sizeof(size), 0));
  uint32_t result = 0;
  ASSERT_EQ(static_cast<ssize_t>(sizeof(result)),
            TEMP_FAILURE_RETRY(recv(fd, &result, sizeof(result), MSG_WAITALL)));
  EXPECT_EQ(static_cast<uint32_t>(PROP_ERROR_READ_DATA), result);
  ASSERT_EQ(0, close(fd));
}

TEST(property_service, non_utf8_value) {
    if (getuid() != 0) {
        GTEST_SKIP() << "Skipping test, must be run as root.";
        return;
    }

    ASSERT_TRUE(SetProperty("property_service_utf8_test", "base_success"));
    EXPECT_FALSE(SetProperty("property_service_utf8_test", "\x80"));
    EXPECT_FALSE(SetProperty("property_service_utf8_test", "\xC2\x01"));
    EXPECT_FALSE(SetProperty("property_service_utf8_test", "\xE0\xFF"));
    EXPECT_FALSE(SetProperty("property_service_utf8_test", "\xE0\xA0\xFF"));
    EXPECT_FALSE(SetProperty("property_service_utf8_test", "\xF0\x01\xFF"));
    EXPECT_FALSE(SetProperty("property_service_utf8_test", "\xF0\x90\xFF"));
    EXPECT_FALSE(SetProperty("property_service_utf8_test", "\xF0\x90\x80\xFF"));
    EXPECT_FALSE(SetProperty("property_service_utf8_test", "\xF0\x90\x80"));
    EXPECT_FALSE(SetProperty("property_service_utf8_test", "ab\xF0\x90\x80\x80qe\xF0\x90\x80"));
    EXPECT_TRUE(SetProperty("property_service_utf8_test", "\xF0\x90\x80\x80"));
}

TEST(property_service, userspace_reboot_not_supported) {
    if (getuid() != 0) {
        GTEST_SKIP() << "Skipping test, must be run as root.";
        return;
    }
    EXPECT_FALSE(SetProperty("sys.powerctl", "reboot,userspace"));
}

TEST(property_service, check_fingerprint_with_legacy_build_id) {
    std::string legacy_build_id = GetProperty("ro.build.legacy.id", "");
    if (legacy_build_id.empty()) {
        GTEST_SKIP() << "Skipping test, legacy build id isn't set.";
    }

    std::string vbmeta_digest = GetProperty("ro.boot.vbmeta.digest", "");
    ASSERT_GE(vbmeta_digest.size(), 8u);
    std::string build_id = GetProperty("ro.build.id", "");
    // Check that the build id is constructed with the prefix of vbmeta digest
    std::string expected_build_id = legacy_build_id + "." + vbmeta_digest.substr(0, 8);
    ASSERT_EQ(expected_build_id, build_id);
    // Check that the fingerprint is constructed with the expected format.
    std::string fingerprint = GetProperty("ro.build.fingerprint", "");
    std::vector<std::string> fingerprint_fields = {
            GetProperty("ro.product.brand", ""),
            "/",
            GetProperty("ro.product.name", ""),
            "/",
            GetProperty("ro.product.device", ""),
            ":",
            GetProperty("ro.build.version.release_or_codename", ""),
            "/",
            expected_build_id,
            "/",
            GetProperty("ro.build.version.incremental", ""),
            ":",
            GetProperty("ro.build.type", ""),
            "/",
            GetProperty("ro.build.tags", "")};

    ASSERT_EQ(android::base::Join(fingerprint_fields, ""), fingerprint);
}

}  // namespace init
}  // namespace android

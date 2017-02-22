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
#include <sys/un.h>

#define _REALLY_INCLUDE_SYS__SYSTEM_PROPERTIES_H_
#include <sys/_system_properties.h>

#include <gtest/gtest.h>

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
  uint32_t data = 0xdeadbeef;

  ASSERT_EQ(static_cast<ssize_t>(sizeof(msg)), send(fd, &msg, sizeof(msg), 0));
  ASSERT_EQ(static_cast<ssize_t>(sizeof(size)), send(fd, &size, sizeof(size), 0));
  ASSERT_EQ(static_cast<ssize_t>(sizeof(data)), send(fd, &data, sizeof(data), 0));
  ASSERT_EQ(0, close(fd));
}

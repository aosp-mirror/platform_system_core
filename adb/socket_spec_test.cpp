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

#include "socket_spec.h"

#include <string>

#include <gtest/gtest.h>

TEST(socket_spec, parse_tcp_socket_spec) {
    std::string hostname, error, serial;
    int port;
    EXPECT_TRUE(parse_tcp_socket_spec("tcp:5037", &hostname, &port, &serial, &error));
    EXPECT_EQ("", hostname);
    EXPECT_EQ(5037, port);
    EXPECT_EQ("", serial);

    // Bad ports:
    EXPECT_FALSE(parse_tcp_socket_spec("tcp:", &hostname, &port, &serial, &error));
    EXPECT_FALSE(parse_tcp_socket_spec("tcp:-1", &hostname, &port, &serial, &error));
    EXPECT_FALSE(parse_tcp_socket_spec("tcp:65536", &hostname, &port, &serial, &error));

    EXPECT_TRUE(parse_tcp_socket_spec("tcp:localhost:1234", &hostname, &port, &serial, &error));
    EXPECT_EQ("localhost", hostname);
    EXPECT_EQ(1234, port);
    EXPECT_EQ("localhost:1234", serial);

    EXPECT_FALSE(parse_tcp_socket_spec("tcp:localhost", &hostname, &port, &serial, &error));
    EXPECT_FALSE(parse_tcp_socket_spec("tcp:localhost:", &hostname, &port, &serial, &error));
    EXPECT_FALSE(parse_tcp_socket_spec("tcp:localhost:-1", &hostname, &port, &serial, &error));
    EXPECT_FALSE(parse_tcp_socket_spec("tcp:localhost:65536", &hostname, &port, &serial, &error));

    // IPv6:
    EXPECT_TRUE(parse_tcp_socket_spec("tcp:[::1]:1234", &hostname, &port, &serial, &error));
    EXPECT_EQ("::1", hostname);
    EXPECT_EQ(1234, port);
    EXPECT_EQ("[::1]:1234", serial);

    EXPECT_FALSE(parse_tcp_socket_spec("tcp:[::1]", &hostname, &port, &serial, &error));
    EXPECT_FALSE(parse_tcp_socket_spec("tcp:[::1]:", &hostname, &port, &serial, &error));
    EXPECT_FALSE(parse_tcp_socket_spec("tcp:[::1]:-1", &hostname, &port, &serial, &error));
    EXPECT_FALSE(parse_tcp_socket_spec("tcp:::1", &hostname, &port, &serial, &error));
    EXPECT_FALSE(parse_tcp_socket_spec("tcp:::1:1234", &hostname, &port, &serial, &error));
}

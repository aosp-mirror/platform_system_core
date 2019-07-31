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

TEST(socket_spec, parse_tcp_socket_spec_just_port) {
    std::string hostname, error, serial;
    int port;
    EXPECT_TRUE(parse_tcp_socket_spec("tcp:5037", &hostname, &port, &serial, &error));
    EXPECT_EQ("", hostname);
    EXPECT_EQ(5037, port);
    EXPECT_EQ("", serial);
}

TEST(socket_spec, parse_tcp_socket_spec_bad_ports) {
    std::string hostname, error, serial;
    int port;
    EXPECT_FALSE(parse_tcp_socket_spec("tcp:", &hostname, &port, &serial, &error));
    EXPECT_FALSE(parse_tcp_socket_spec("tcp:-1", &hostname, &port, &serial, &error));
    EXPECT_FALSE(parse_tcp_socket_spec("tcp:65536", &hostname, &port, &serial, &error));
}

TEST(socket_spec, parse_tcp_socket_spec_host_and_port) {
    std::string hostname, error, serial;
    int port;
    EXPECT_TRUE(parse_tcp_socket_spec("tcp:localhost:1234", &hostname, &port, &serial, &error));
    EXPECT_EQ("localhost", hostname);
    EXPECT_EQ(1234, port);
    EXPECT_EQ("localhost:1234", serial);
}

TEST(socket_spec, parse_tcp_socket_spec_host_no_port) {
    std::string hostname, error, serial;
    int port;
    EXPECT_TRUE(parse_tcp_socket_spec("tcp:localhost", &hostname, &port, &serial, &error));
    EXPECT_EQ("localhost", hostname);
    EXPECT_EQ(5555, port);
    EXPECT_EQ("localhost:5555", serial);
}

TEST(socket_spec, parse_tcp_socket_spec_host_bad_ports) {
    std::string hostname, error, serial;
    int port;
    EXPECT_FALSE(parse_tcp_socket_spec("tcp:localhost:", &hostname, &port, &serial, &error));
    EXPECT_FALSE(parse_tcp_socket_spec("tcp:localhost:-1", &hostname, &port, &serial, &error));
    EXPECT_FALSE(parse_tcp_socket_spec("tcp:localhost:65536", &hostname, &port, &serial, &error));
}

TEST(socket_spec, parse_tcp_socket_spec_ipv6_and_port) {
    std::string hostname, error, serial;
    int port;
    EXPECT_TRUE(parse_tcp_socket_spec("tcp:[::1]:1234", &hostname, &port, &serial, &error));
    EXPECT_EQ("::1", hostname);
    EXPECT_EQ(1234, port);
    EXPECT_EQ("[::1]:1234", serial);
}

TEST(socket_spec, parse_tcp_socket_spec_ipv6_no_port) {
    std::string hostname, error, serial;
    int port;
    EXPECT_TRUE(parse_tcp_socket_spec("tcp:::1", &hostname, &port, &serial, &error));
    EXPECT_EQ("::1", hostname);
    EXPECT_EQ(5555, port);
    EXPECT_EQ("[::1]:5555", serial);
}

TEST(socket_spec, parse_tcp_socket_spec_ipv6_bad_ports) {
    std::string hostname, error, serial;
    int port;
    EXPECT_FALSE(parse_tcp_socket_spec("tcp:[::1]", &hostname, &port, &serial, &error));
    EXPECT_FALSE(parse_tcp_socket_spec("tcp:[::1]:", &hostname, &port, &serial, &error));
    EXPECT_FALSE(parse_tcp_socket_spec("tcp:[::1]:-1", &hostname, &port, &serial, &error));
}

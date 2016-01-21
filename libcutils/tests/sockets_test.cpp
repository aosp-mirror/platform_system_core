/*
 * Copyright (C) 2015 The Android Open Source Project
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

// Tests socket functionality using loopback connections. Requires IPv4 and
// IPv6 capabilities, and that kTestPort is available for loopback
// communication. These tests also assume that no UDP packets are lost,
// which should be the case for loopback communication, but is not guaranteed.

#include <cutils/sockets.h>

#include <gtest/gtest.h>

enum {
    // This port must be available for loopback communication.
    kTestPort = 54321
};

// Makes sure the passed sockets are valid, sends data between them, and closes
// them. Any failures are logged with gtest.
//
// On Mac recvfrom() will not fill in the address for TCP sockets, so we need
// separate logic paths depending on socket type.
static void TestConnectedSockets(cutils_socket_t server, cutils_socket_t client,
                                 int type) {
    ASSERT_NE(INVALID_SOCKET, server);
    ASSERT_NE(INVALID_SOCKET, client);

    char buffer[3];
    sockaddr_storage addr;
    socklen_t addr_size = sizeof(addr);

    // Send client -> server first to get the UDP client's address.
    ASSERT_EQ(3, send(client, "foo", 3, 0));
    if (type == SOCK_DGRAM) {
      EXPECT_EQ(3, recvfrom(server, buffer, 3, 0,
                            reinterpret_cast<sockaddr*>(&addr), &addr_size));
    } else {
      EXPECT_EQ(3, recv(server, buffer, 3, 0));
    }
    EXPECT_EQ(0, memcmp(buffer, "foo", 3));

    // Now send server -> client.
    if (type == SOCK_DGRAM) {
      ASSERT_EQ(3, sendto(server, "bar", 3, 0,
                          reinterpret_cast<sockaddr*>(&addr), addr_size));
    } else {
      ASSERT_EQ(3, send(server, "bar", 3, 0));
    }
    EXPECT_EQ(3, recv(client, buffer, 3, 0));
    EXPECT_EQ(0, memcmp(buffer, "bar", 3));

    EXPECT_EQ(0, socket_close(server));
    EXPECT_EQ(0, socket_close(client));
}

// Tests socket_inaddr_any_server() and socket_network_client() for IPv4 UDP.
TEST(SocketsTest, TestIpv4UdpLoopback) {
    cutils_socket_t server = socket_inaddr_any_server(kTestPort, SOCK_DGRAM);
    cutils_socket_t client = socket_network_client("127.0.0.1", kTestPort,
                                                   SOCK_DGRAM);

    TestConnectedSockets(server, client, SOCK_DGRAM);
}

// Tests socket_inaddr_any_server() and socket_network_client() for IPv4 TCP.
TEST(SocketsTest, TestIpv4TcpLoopback) {
    cutils_socket_t server = socket_inaddr_any_server(kTestPort, SOCK_STREAM);
    ASSERT_NE(INVALID_SOCKET, server);

    cutils_socket_t client = socket_network_client("127.0.0.1", kTestPort,
                                                   SOCK_STREAM);
    cutils_socket_t handler = accept(server, nullptr, nullptr);
    EXPECT_EQ(0, socket_close(server));

    TestConnectedSockets(handler, client, SOCK_STREAM);
}

// Tests socket_inaddr_any_server() and socket_network_client() for IPv6 UDP.
TEST(SocketsTest, TestIpv6UdpLoopback) {
    cutils_socket_t server = socket_inaddr_any_server(kTestPort, SOCK_DGRAM);
    cutils_socket_t client = socket_network_client("::1", kTestPort,
                                                   SOCK_DGRAM);

    TestConnectedSockets(server, client, SOCK_DGRAM);
}

// Tests socket_inaddr_any_server() and socket_network_client() for IPv6 TCP.
TEST(SocketsTest, TestIpv6TcpLoopback) {
    cutils_socket_t server = socket_inaddr_any_server(kTestPort, SOCK_STREAM);
    ASSERT_NE(INVALID_SOCKET, server);

    cutils_socket_t client = socket_network_client("::1", kTestPort,
                                                   SOCK_STREAM);
    cutils_socket_t handler = accept(server, nullptr, nullptr);
    EXPECT_EQ(0, socket_close(server));

    TestConnectedSockets(handler, client, SOCK_STREAM);
}

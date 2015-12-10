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

// Tests UDP functionality using loopback connections. Requires that kDefaultPort is available
// for loopback communication on the host. These tests also assume that no UDP packets are lost,
// which should be the case for loopback communication, but is not guaranteed.

#include "socket.h"

#include <errno.h>
#include <time.h>

#include <memory>
#include <string>
#include <vector>

#include <gtest/gtest.h>

enum {
    // This port must be available for loopback communication.
    kDefaultPort = 54321,

    // Don't wait forever in a unit test.
    kDefaultTimeoutMs = 3000,
};

static const char kReceiveStringError[] = "Error receiving string";

// Test fixture to provide some helper functions. Makes each test a little simpler since we can
// just check a bool for socket creation and don't have to pass hostname or port information.
class SocketTest : public ::testing::Test {
  protected:
    bool StartServer(int port = kDefaultPort) {
        server_ = UdpSocket::NewUdpServer(port);
        return server_ != nullptr;
    }

    bool StartClient(const std::string hostname = "localhost", int port = kDefaultPort) {
        client_ = UdpSocket::NewUdpClient(hostname, port, nullptr);
        return client_ != nullptr;
    }

    bool StartClient2(const std::string hostname = "localhost", int port = kDefaultPort) {
        client2_ = UdpSocket::NewUdpClient(hostname, port, nullptr);
        return client2_ != nullptr;
    }

    std::unique_ptr<UdpSocket> server_, client_, client2_;
};

// Sends a string over a UdpSocket. Returns true if the full string (without terminating char)
// was sent.
static bool SendString(UdpSocket* udp, const std::string& message) {
    return udp->Send(message.c_str(), message.length()) == static_cast<ssize_t>(message.length());
}

// Receives a string from a UdpSocket. Returns the string, or kReceiveStringError on failure.
static std::string ReceiveString(UdpSocket* udp, size_t receive_size = 128) {
    std::vector<char> buffer(receive_size);

    ssize_t result = udp->Receive(buffer.data(), buffer.size(), kDefaultTimeoutMs);
    if (result >= 0) {
        return std::string(buffer.data(), result);
    }
    return kReceiveStringError;
}

// Calls Receive() on the UdpSocket with the given timeout. Returns true if the call timed out.
static bool ReceiveTimeout(UdpSocket* udp, int timeout_ms) {
    char buffer[1];

    errno = 0;
    return udp->Receive(buffer, 1, timeout_ms) == -1 && (errno == EAGAIN || errno == EWOULDBLOCK);
}

// Tests sending packets client -> server, then server -> client.
TEST_F(SocketTest, SendAndReceive) {
    ASSERT_TRUE(StartServer());
    ASSERT_TRUE(StartClient());

    EXPECT_TRUE(SendString(client_.get(), "foo"));
    EXPECT_EQ("foo", ReceiveString(server_.get()));

    EXPECT_TRUE(SendString(server_.get(), "bar baz"));
    EXPECT_EQ("bar baz", ReceiveString(client_.get()));
}

// Tests sending and receiving large packets.
TEST_F(SocketTest, LargePackets) {
    std::string message(512, '\0');

    ASSERT_TRUE(StartServer());
    ASSERT_TRUE(StartClient());

    // Run through the test a few times.
    for (int i = 0; i < 10; ++i) {
        // Use a different message each iteration to prevent false positives.
        for (size_t j = 0; j < message.length(); ++j) {
            message[j] = static_cast<char>(i + j);
        }

        EXPECT_TRUE(SendString(client_.get(), message));
        EXPECT_EQ(message, ReceiveString(server_.get(), message.length()));
    }
}

// Tests IPv4 client/server.
TEST_F(SocketTest, IPv4) {
    ASSERT_TRUE(StartServer());
    ASSERT_TRUE(StartClient("127.0.0.1"));

    EXPECT_TRUE(SendString(client_.get(), "foo"));
    EXPECT_EQ("foo", ReceiveString(server_.get()));

    EXPECT_TRUE(SendString(server_.get(), "bar"));
    EXPECT_EQ("bar", ReceiveString(client_.get()));
}

// Tests IPv6 client/server.
TEST_F(SocketTest, IPv6) {
    ASSERT_TRUE(StartServer());
    ASSERT_TRUE(StartClient("::1"));

    EXPECT_TRUE(SendString(client_.get(), "foo"));
    EXPECT_EQ("foo", ReceiveString(server_.get()));

    EXPECT_TRUE(SendString(server_.get(), "bar"));
    EXPECT_EQ("bar", ReceiveString(client_.get()));
}

// Tests receive timeout. The timing verification logic must be very coarse to make sure different
// systems running different loads can all pass these tests.
TEST_F(SocketTest, ReceiveTimeout) {
    time_t start_time;

    ASSERT_TRUE(StartServer());

    // Make sure a 20ms timeout completes in 1 second or less.
    start_time = time(nullptr);
    EXPECT_TRUE(ReceiveTimeout(server_.get(), 20));
    EXPECT_LE(difftime(time(nullptr), start_time), 1.0);

    // Make sure a 1250ms timeout takes 1 second or more.
    start_time = time(nullptr);
    EXPECT_TRUE(ReceiveTimeout(server_.get(), 1250));
    EXPECT_LE(1.0, difftime(time(nullptr), start_time));
}

// Tests receive overflow (the UDP packet is larger than the receive buffer).
TEST_F(SocketTest, ReceiveOverflow) {
    ASSERT_TRUE(StartServer());
    ASSERT_TRUE(StartClient());

    EXPECT_TRUE(SendString(client_.get(), "1234567890"));

    // This behaves differently on different systems; some give us a truncated UDP packet, others
    // will error out and not return anything at all.
    std::string rx_string = ReceiveString(server_.get(), 5);

    // If we didn't get an error then the packet should have been truncated.
    if (rx_string != kReceiveStringError) {
        EXPECT_EQ("12345", rx_string);
    }
}

// Tests multiple clients sending to the same server.
TEST_F(SocketTest, MultipleClients) {
    ASSERT_TRUE(StartServer());
    ASSERT_TRUE(StartClient());
    ASSERT_TRUE(StartClient2());

    EXPECT_TRUE(SendString(client_.get(), "client"));
    EXPECT_TRUE(SendString(client2_.get(), "client2"));

    // Receive the packets and send a response for each (note that packets may be received
    // out-of-order).
    for (int i = 0; i < 2; ++i) {
        std::string received = ReceiveString(server_.get());
        EXPECT_TRUE(SendString(server_.get(), received + " response"));
    }

    EXPECT_EQ("client response", ReceiveString(client_.get()));
    EXPECT_EQ("client2 response", ReceiveString(client2_.get()));
}

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

// Tests socket functionality using loopback connections. The UDP tests assume that no packets are
// lost, which should be the case for loopback communication, but is not guaranteed.
//
// Also tests our SocketMock class to make sure it works as expected and reports errors properly
// if the mock expectations aren't met during a test.

#include "socket.h"
#include "socket_mock.h"

#include <gtest/gtest.h>
#include <gtest/gtest-spi.h>

enum { kTestTimeoutMs = 3000 };

// Creates connected sockets |server| and |client|. Returns true on success.
bool MakeConnectedSockets(Socket::Protocol protocol, std::unique_ptr<Socket>* server,
                          std::unique_ptr<Socket>* client,
                          const std::string hostname = "localhost") {
    *server = Socket::NewServer(protocol, 0);
    if (*server == nullptr) {
        ADD_FAILURE() << "Failed to create server.";
        return false;
    }

    *client = Socket::NewClient(protocol, hostname, (*server)->GetLocalPort(), nullptr);
    if (*client == nullptr) {
        ADD_FAILURE() << "Failed to create client.";
        return false;
    }

    // TCP passes the client off to a new socket.
    if (protocol == Socket::Protocol::kTcp) {
        *server = (*server)->Accept();
        if (*server == nullptr) {
            ADD_FAILURE() << "Failed to accept client connection.";
            return false;
        }
    }

    return true;
}

// Sends a string over a Socket. Returns true if the full string (without terminating char)
// was sent.
static bool SendString(Socket* sock, const std::string& message) {
    return sock->Send(message.c_str(), message.length()) == static_cast<ssize_t>(message.length());
}

// Receives a string from a Socket. Returns true if the full string (without terminating char)
// was received.
static bool ReceiveString(Socket* sock, const std::string& message) {
    std::string received(message.length(), '\0');
    ssize_t bytes = sock->ReceiveAll(&received[0], received.length(), kTestTimeoutMs);
    return static_cast<size_t>(bytes) == received.length() && received == message;
}

// Tests sending packets client -> server, then server -> client.
TEST(SocketTest, TestSendAndReceive) {
    std::unique_ptr<Socket> server, client;

    for (Socket::Protocol protocol : {Socket::Protocol::kUdp, Socket::Protocol::kTcp}) {
        ASSERT_TRUE(MakeConnectedSockets(protocol, &server, &client));

        EXPECT_TRUE(SendString(client.get(), "foo"));
        EXPECT_TRUE(ReceiveString(server.get(), "foo"));

        EXPECT_TRUE(SendString(server.get(), "bar baz"));
        EXPECT_TRUE(ReceiveString(client.get(), "bar baz"));
    }
}

// Tests sending and receiving large packets.
TEST(SocketTest, TestLargePackets) {
    std::string message(1024, '\0');
    std::unique_ptr<Socket> server, client;

    for (Socket::Protocol protocol : {Socket::Protocol::kUdp, Socket::Protocol::kTcp}) {
        ASSERT_TRUE(MakeConnectedSockets(protocol, &server, &client));

        // Run through the test a few times.
        for (int i = 0; i < 10; ++i) {
            // Use a different message each iteration to prevent false positives.
            for (size_t j = 0; j < message.length(); ++j) {
                message[j] = static_cast<char>(i + j);
            }

            EXPECT_TRUE(SendString(client.get(), message));
            EXPECT_TRUE(ReceiveString(server.get(), message));
        }
    }
}

// Tests UDP receive overflow when the UDP packet is larger than the receive buffer.
TEST(SocketTest, TestUdpReceiveOverflow) {
    std::unique_ptr<Socket> server, client;
    ASSERT_TRUE(MakeConnectedSockets(Socket::Protocol::kUdp, &server, &client));

    EXPECT_TRUE(SendString(client.get(), "1234567890"));

    // This behaves differently on different systems, either truncating the packet or returning -1.
    char buffer[5];
    ssize_t bytes = server->Receive(buffer, 5, kTestTimeoutMs);
    if (bytes == 5) {
        EXPECT_EQ(0, memcmp(buffer, "12345", 5));
    } else {
        EXPECT_EQ(-1, bytes);
    }
}

TEST(SocketMockTest, TestSendSuccess) {
    SocketMock mock;

    mock.ExpectSend("foo");
    EXPECT_TRUE(SendString(&mock, "foo"));

    mock.ExpectSend("abc");
    mock.ExpectSend("123");
    EXPECT_TRUE(SendString(&mock, "abc"));
    EXPECT_TRUE(SendString(&mock, "123"));
}

TEST(SocketMockTest, TestSendFailure) {
    SocketMock* mock = new SocketMock;

    EXPECT_NONFATAL_FAILURE(SendString(mock, "foo"), "no message was expected");

    mock->ExpectSend("foo");
    EXPECT_NONFATAL_FAILURE(SendString(mock, "bar"), "expected foo, but got bar");
    EXPECT_TRUE(SendString(mock, "foo"));

    mock->AddReceive("foo");
    EXPECT_NONFATAL_FAILURE(SendString(mock, "foo"), "called out-of-order");
    EXPECT_TRUE(ReceiveString(mock, "foo"));

    mock->ExpectSend("foo");
    EXPECT_NONFATAL_FAILURE(delete mock, "1 event(s) were not handled");
}

TEST(SocketMockTest, TestReceiveSuccess) {
    SocketMock mock;

    mock.AddReceive("foo");
    EXPECT_TRUE(ReceiveString(&mock, "foo"));

    mock.AddReceive("abc");
    mock.AddReceive("123");
    EXPECT_TRUE(ReceiveString(&mock, "abc"));
    EXPECT_TRUE(ReceiveString(&mock, "123"));
}

TEST(SocketMockTest, TestReceiveFailure) {
    SocketMock* mock = new SocketMock;

    EXPECT_NONFATAL_FAILURE(ReceiveString(mock, "foo"), "no message was ready");

    mock->ExpectSend("foo");
    EXPECT_NONFATAL_FAILURE(ReceiveString(mock, "foo"), "called out-of-order");
    EXPECT_TRUE(SendString(mock, "foo"));

    char c;
    mock->AddReceive("foo");
    EXPECT_NONFATAL_FAILURE(mock->Receive(&c, 1, 0), "not enough bytes (1) for foo");
    EXPECT_TRUE(ReceiveString(mock, "foo"));

    mock->AddReceive("foo");
    EXPECT_NONFATAL_FAILURE(delete mock, "1 event(s) were not handled");
}

TEST(SocketMockTest, TestAcceptSuccess) {
    SocketMock mock;

    SocketMock* mock_handler = new SocketMock;
    mock.AddAccept(std::unique_ptr<SocketMock>(mock_handler));
    EXPECT_EQ(mock_handler, mock.Accept().get());

    mock.AddAccept(nullptr);
    EXPECT_EQ(nullptr, mock.Accept().get());
}

TEST(SocketMockTest, TestAcceptFailure) {
    SocketMock* mock = new SocketMock;

    EXPECT_NONFATAL_FAILURE(mock->Accept(), "no socket was ready");

    mock->ExpectSend("foo");
    EXPECT_NONFATAL_FAILURE(mock->Accept(), "called out-of-order");
    EXPECT_TRUE(SendString(mock, "foo"));

    mock->AddAccept(nullptr);
    EXPECT_NONFATAL_FAILURE(delete mock, "1 event(s) were not handled");
}

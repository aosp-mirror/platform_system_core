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

#include <list>

#include <gtest/gtest-spi.h>
#include <gtest/gtest.h>

static constexpr int kShortTimeoutMs = 10;
static constexpr int kTestTimeoutMs = 3000;

// Creates connected sockets |server| and |client|. Returns true on success.
bool MakeConnectedSockets(Socket::Protocol protocol, std::unique_ptr<Socket>* server,
                          std::unique_ptr<Socket>* client,
                          const std::string& hostname = "localhost") {
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
    return sock->Send(message.c_str(), message.length());
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

TEST(SocketTest, TestReceiveTimeout) {
    std::unique_ptr<Socket> server, client;
    char buffer[16];

    for (Socket::Protocol protocol : {Socket::Protocol::kUdp, Socket::Protocol::kTcp}) {
        ASSERT_TRUE(MakeConnectedSockets(protocol, &server, &client));

        EXPECT_EQ(-1, server->Receive(buffer, sizeof(buffer), kShortTimeoutMs));
        EXPECT_TRUE(server->ReceiveTimedOut());

        EXPECT_EQ(-1, client->Receive(buffer, sizeof(buffer), kShortTimeoutMs));
        EXPECT_TRUE(client->ReceiveTimedOut());
    }

    // UDP will wait for timeout if the other side closes.
    ASSERT_TRUE(MakeConnectedSockets(Socket::Protocol::kUdp, &server, &client));
    EXPECT_EQ(0, server->Close());
    EXPECT_EQ(-1, client->Receive(buffer, sizeof(buffer), kShortTimeoutMs));
    EXPECT_TRUE(client->ReceiveTimedOut());
}

TEST(SocketTest, TestReceiveFailure) {
    std::unique_ptr<Socket> server, client;
    char buffer[16];

    for (Socket::Protocol protocol : {Socket::Protocol::kUdp, Socket::Protocol::kTcp}) {
        ASSERT_TRUE(MakeConnectedSockets(protocol, &server, &client));

        EXPECT_EQ(0, server->Close());
        EXPECT_EQ(-1, server->Receive(buffer, sizeof(buffer), kTestTimeoutMs));
        EXPECT_FALSE(server->ReceiveTimedOut());

        EXPECT_EQ(0, client->Close());
        EXPECT_EQ(-1, client->Receive(buffer, sizeof(buffer), kTestTimeoutMs));
        EXPECT_FALSE(client->ReceiveTimedOut());
    }

    // TCP knows right away when the other side closes and returns 0 to indicate EOF.
    ASSERT_TRUE(MakeConnectedSockets(Socket::Protocol::kTcp, &server, &client));
    EXPECT_EQ(0, server->Close());
    EXPECT_EQ(0, client->Receive(buffer, sizeof(buffer), kTestTimeoutMs));
    EXPECT_FALSE(client->ReceiveTimedOut());
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

// Tests UDP multi-buffer send.
TEST(SocketTest, TestUdpSendBuffers) {
    std::unique_ptr<Socket> sock = Socket::NewServer(Socket::Protocol::kUdp, 0);
    std::vector<std::string> data{"foo", "bar", "12345"};
    std::vector<cutils_socket_buffer_t> buffers{{data[0].data(), data[0].length()},
                                                {data[1].data(), data[1].length()},
                                                {data[2].data(), data[2].length()}};
    ssize_t mock_return_value = 0;

    // Mock out socket_send_buffers() to verify we're sending in the correct buffers and
    // return |mock_return_value|.
    sock->socket_send_buffers_function_ = [&buffers, &mock_return_value](
            cutils_socket_t /*cutils_sock*/, cutils_socket_buffer_t* sent_buffers,
            size_t num_sent_buffers) -> ssize_t {
        EXPECT_EQ(buffers.size(), num_sent_buffers);
        for (size_t i = 0; i < num_sent_buffers; ++i) {
            EXPECT_EQ(buffers[i].data, sent_buffers[i].data);
            EXPECT_EQ(buffers[i].length, sent_buffers[i].length);
        }
        return mock_return_value;
    };

    mock_return_value = strlen("foobar12345");
    EXPECT_TRUE(sock->Send(buffers));

    mock_return_value -= 1;
    EXPECT_FALSE(sock->Send(buffers));

    mock_return_value = 0;
    EXPECT_FALSE(sock->Send(buffers));

    mock_return_value = -1;
    EXPECT_FALSE(sock->Send(buffers));
}

// Tests TCP re-sending until socket_send_buffers() sends all data. This is a little complicated,
// but the general idea is that we intercept calls to socket_send_buffers() using a lambda mock
// function that simulates partial writes.
TEST(SocketTest, TestTcpSendBuffers) {
    std::unique_ptr<Socket> sock = Socket::NewServer(Socket::Protocol::kTcp, 0);
    std::vector<std::string> data{"foo", "bar", "12345"};
    std::vector<cutils_socket_buffer_t> buffers{{data[0].data(), data[0].length()},
                                                {data[1].data(), data[1].length()},
                                                {data[2].data(), data[2].length()}};

    // Test breaking up the buffered send at various points.
    std::list<std::string> test_sends[] = {
            // Successes.
            {"foobar12345"},
            {"f", "oob", "ar12345"},
            {"fo", "obar12", "345"},
            {"foo", "bar12345"},
            {"foob", "ar123", "45"},
            {"f", "o", "o", "b", "a", "r", "1", "2", "3", "4", "5"},

            // Failures.
            {},
            {"f"},
            {"foo", "bar"},
            {"fo", "obar12"},
            {"foobar1234"}
    };

    for (auto& test : test_sends) {
        ssize_t bytes_sent = 0;
        bool expect_success = true;

        // Create a mock function for custom socket_send_buffers() behavior. This function will
        // check to make sure the input buffers start at the next unsent byte, then return the
        // number of bytes indicated by the next entry in |test|.
        sock->socket_send_buffers_function_ = [&bytes_sent, &data, &expect_success, &test](
                cutils_socket_t /*cutils_sock*/, cutils_socket_buffer_t* buffers,
                size_t num_buffers) -> ssize_t {
            EXPECT_TRUE(num_buffers > 0);

            // Failure case - pretend we errored out before sending all the buffers.
            if (test.empty()) {
                expect_success = false;
                return -1;
            }

            // Count the bytes we've sent to find where the next buffer should start and how many
            // bytes should be left in it.
            size_t byte_count = bytes_sent, data_index = 0;
            while (data_index < data.size()) {
                if (byte_count >= data[data_index].length()) {
                    byte_count -= data[data_index].length();
                    ++data_index;
                } else {
                    break;
                }
            }
            void* expected_next_byte = &data[data_index][byte_count];
            size_t expected_next_size = data[data_index].length() - byte_count;

            EXPECT_EQ(data.size() - data_index, num_buffers);
            EXPECT_EQ(expected_next_byte, buffers[0].data);
            EXPECT_EQ(expected_next_size, buffers[0].length);

            std::string to_send = std::move(test.front());
            test.pop_front();
            bytes_sent += to_send.length();
            return to_send.length();
        };

        EXPECT_EQ(expect_success, sock->Send(buffers));
        EXPECT_TRUE(test.empty());
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

    mock->ExpectSendFailure("foo");
    EXPECT_FALSE(SendString(mock, "foo"));

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

    // Make sure ReceiveAll() can piece together multiple receives.
    mock.AddReceive("foo");
    mock.AddReceive("bar");
    mock.AddReceive("123");
    EXPECT_TRUE(ReceiveString(&mock, "foobar123"));
}

TEST(SocketMockTest, TestReceiveFailure) {
    SocketMock* mock = new SocketMock;

    mock->AddReceiveFailure();
    EXPECT_FALSE(ReceiveString(mock, "foo"));
    EXPECT_FALSE(mock->ReceiveTimedOut());

    mock->AddReceiveTimeout();
    EXPECT_FALSE(ReceiveString(mock, "foo"));
    EXPECT_TRUE(mock->ReceiveTimedOut());

    mock->AddReceive("foo");
    mock->AddReceiveFailure();
    EXPECT_FALSE(ReceiveString(mock, "foobar"));

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

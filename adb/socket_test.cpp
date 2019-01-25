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

#include "fdevent.h"

#include <gtest/gtest.h>

#include <array>
#include <limits>
#include <queue>
#include <string>
#include <thread>
#include <vector>

#include <unistd.h>

#include "adb.h"
#include "adb_io.h"
#include "fdevent_test.h"
#include "socket.h"
#include "sysdeps.h"
#include "sysdeps/chrono.h"

using namespace std::string_literals;
using namespace std::string_view_literals;

struct ThreadArg {
    int first_read_fd;
    int last_write_fd;
    size_t middle_pipe_count;
};

class LocalSocketTest : public FdeventTest {};

TEST_F(LocalSocketTest, smoke) {
    // Join two socketpairs with a chain of intermediate socketpairs.
    int first[2];
    std::vector<std::array<int, 2>> intermediates;
    int last[2];

    constexpr size_t INTERMEDIATE_COUNT = 50;
    constexpr size_t MESSAGE_LOOP_COUNT = 100;
    const std::string MESSAGE = "socket_test";

    intermediates.resize(INTERMEDIATE_COUNT);
    ASSERT_EQ(0, adb_socketpair(first)) << strerror(errno);
    ASSERT_EQ(0, adb_socketpair(last)) << strerror(errno);
    asocket* prev_tail = create_local_socket(unique_fd(first[1]));
    ASSERT_NE(nullptr, prev_tail);

    auto connect = [](asocket* tail, asocket* head) {
        tail->peer = head;
        head->peer = tail;
        tail->ready(tail);
    };

    for (auto& intermediate : intermediates) {
        ASSERT_EQ(0, adb_socketpair(intermediate.data())) << strerror(errno);

        asocket* head = create_local_socket(unique_fd(intermediate[0]));
        ASSERT_NE(nullptr, head);

        asocket* tail = create_local_socket(unique_fd(intermediate[1]));
        ASSERT_NE(nullptr, tail);

        connect(prev_tail, head);
        prev_tail = tail;
    }

    asocket* end = create_local_socket(unique_fd(last[0]));
    ASSERT_NE(nullptr, end);
    connect(prev_tail, end);

    PrepareThread();

    for (size_t i = 0; i < MESSAGE_LOOP_COUNT; ++i) {
        std::string read_buffer = MESSAGE;
        std::string write_buffer(MESSAGE.size(), 'a');
        ASSERT_TRUE(WriteFdExactly(first[0], &read_buffer[0], read_buffer.size()));
        ASSERT_TRUE(ReadFdExactly(last[1], &write_buffer[0], write_buffer.size()));
        ASSERT_EQ(read_buffer, write_buffer);
    }

    ASSERT_EQ(0, adb_close(first[0]));
    ASSERT_EQ(0, adb_close(last[1]));

    // Wait until the local sockets are closed.
    WaitForFdeventLoop();
    ASSERT_EQ(GetAdditionalLocalSocketCount(), fdevent_installed_count());
    TerminateThread();
}

struct CloseWithPacketArg {
    unique_fd socket_fd;
    size_t bytes_written;
    unique_fd cause_close_fd;
};

static void CreateCloser(CloseWithPacketArg* arg) {
    fdevent_run_on_main_thread([arg]() {
        asocket* s = create_local_socket(std::move(arg->socket_fd));
        ASSERT_TRUE(s != nullptr);
        arg->bytes_written = 0;

        // On platforms that implement sockets via underlying sockets (e.g. Wine),
        // a socket can appear to be full, and then become available for writes
        // again without read being called on the other end. Loop and sleep after
        // each write to give the underlying implementation time to flush.
        bool socket_filled = false;
        for (int i = 0; i < 128; ++i) {
            apacket::payload_type data;
            data.resize(MAX_PAYLOAD);
            arg->bytes_written += data.size();
            int ret = s->enqueue(s, std::move(data));
            if (ret == 1) {
                socket_filled = true;
                break;
            }
            ASSERT_NE(-1, ret);

            std::this_thread::sleep_for(250ms);
        }
        ASSERT_TRUE(socket_filled);

        asocket* cause_close_s = create_local_socket(std::move(arg->cause_close_fd));
        ASSERT_TRUE(cause_close_s != nullptr);
        cause_close_s->peer = s;
        s->peer = cause_close_s;
        cause_close_s->ready(cause_close_s);
    });
    WaitForFdeventLoop();
}

// This test checks if we can close local socket in the following situation:
// The socket is closing but having some packets, so it is not closed. Then
// some write error happens in the socket's file handler, e.g., the file
// handler is closed.
TEST_F(LocalSocketTest, close_socket_with_packet) {
    int socket_fd[2];
    ASSERT_EQ(0, adb_socketpair(socket_fd));
    int cause_close_fd[2];
    ASSERT_EQ(0, adb_socketpair(cause_close_fd));
    CloseWithPacketArg arg;
    arg.socket_fd.reset(socket_fd[1]);
    arg.cause_close_fd.reset(cause_close_fd[1]);

    PrepareThread();
    CreateCloser(&arg);

    ASSERT_EQ(0, adb_close(cause_close_fd[0]));

    WaitForFdeventLoop();
    EXPECT_EQ(1u + GetAdditionalLocalSocketCount(), fdevent_installed_count());
    ASSERT_EQ(0, adb_close(socket_fd[0]));

    WaitForFdeventLoop();
    ASSERT_EQ(GetAdditionalLocalSocketCount(), fdevent_installed_count());
    TerminateThread();
}

// This test checks if we can read packets from a closing local socket.
TEST_F(LocalSocketTest, read_from_closing_socket) {
    int socket_fd[2];
    ASSERT_EQ(0, adb_socketpair(socket_fd));
    int cause_close_fd[2];
    ASSERT_EQ(0, adb_socketpair(cause_close_fd));
    CloseWithPacketArg arg;
    arg.socket_fd.reset(socket_fd[1]);
    arg.cause_close_fd.reset(cause_close_fd[1]);

    PrepareThread();
    CreateCloser(&arg);

    WaitForFdeventLoop();
    ASSERT_EQ(0, adb_close(cause_close_fd[0]));

    WaitForFdeventLoop();
    EXPECT_EQ(1u + GetAdditionalLocalSocketCount(), fdevent_installed_count());

    // Verify if we can read successfully.
    std::vector<char> buf(arg.bytes_written);
    ASSERT_NE(0u, arg.bytes_written);
    ASSERT_EQ(true, ReadFdExactly(socket_fd[0], buf.data(), buf.size()));
    ASSERT_EQ(0, adb_close(socket_fd[0]));

    WaitForFdeventLoop();
    ASSERT_EQ(GetAdditionalLocalSocketCount(), fdevent_installed_count());
    TerminateThread();
}

// This test checks if we can close local socket in the following situation:
// The socket is not closed and has some packets. When it fails to write to
// the socket's file handler because the other end is closed, we check if the
// socket is closed.
TEST_F(LocalSocketTest, write_error_when_having_packets) {
    int socket_fd[2];
    ASSERT_EQ(0, adb_socketpair(socket_fd));
    int cause_close_fd[2];
    ASSERT_EQ(0, adb_socketpair(cause_close_fd));
    CloseWithPacketArg arg;
    arg.socket_fd.reset(socket_fd[1]);
    arg.cause_close_fd.reset(cause_close_fd[1]);

    PrepareThread();
    CreateCloser(&arg);

    WaitForFdeventLoop();
    EXPECT_EQ(2u + GetAdditionalLocalSocketCount(), fdevent_installed_count());
    ASSERT_EQ(0, adb_close(socket_fd[0]));

    WaitForFdeventLoop();
    ASSERT_EQ(GetAdditionalLocalSocketCount(), fdevent_installed_count());
    TerminateThread();
}

// Ensure that if we fail to write output to an fd, we will still flush data coming from it.
TEST_F(LocalSocketTest, flush_after_shutdown) {
    int head_fd[2];
    int tail_fd[2];
    ASSERT_EQ(0, adb_socketpair(head_fd));
    ASSERT_EQ(0, adb_socketpair(tail_fd));

    asocket* head = create_local_socket(unique_fd(head_fd[1]));
    asocket* tail = create_local_socket(unique_fd(tail_fd[1]));

    head->peer = tail;
    head->ready(head);

    tail->peer = head;
    tail->ready(tail);

    PrepareThread();

    EXPECT_TRUE(WriteFdExactly(head_fd[0], "foo", 3));

    EXPECT_EQ(0, adb_shutdown(head_fd[0], SHUT_RD));
    const char* str = "write succeeds, but local_socket will fail to write";
    EXPECT_TRUE(WriteFdExactly(tail_fd[0], str, strlen(str)));
    EXPECT_TRUE(WriteFdExactly(head_fd[0], "bar", 3));

    char buf[6];
    EXPECT_TRUE(ReadFdExactly(tail_fd[0], buf, 6));
    EXPECT_EQ(0, memcmp(buf, "foobar", 6));

    adb_close(head_fd[0]);
    adb_close(tail_fd[0]);

    WaitForFdeventLoop();
    ASSERT_EQ(GetAdditionalLocalSocketCount(), fdevent_installed_count());
    TerminateThread();
}

#if defined(__linux__)

static void ClientThreadFunc() {
    std::string error;
    int fd = network_loopback_client(5038, SOCK_STREAM, &error);
    ASSERT_GE(fd, 0) << error;
    std::this_thread::sleep_for(1s);
    ASSERT_EQ(0, adb_close(fd));
}

// This test checks if we can close sockets in CLOSE_WAIT state.
TEST_F(LocalSocketTest, close_socket_in_CLOSE_WAIT_state) {
    std::string error;
    int listen_fd = network_inaddr_any_server(5038, SOCK_STREAM, &error);
    ASSERT_GE(listen_fd, 0);

    std::thread client_thread(ClientThreadFunc);

    int accept_fd = adb_socket_accept(listen_fd, nullptr, nullptr);
    ASSERT_GE(accept_fd, 0);

    PrepareThread();

    fdevent_run_on_main_thread([accept_fd]() {
        asocket* s = create_local_socket(unique_fd(accept_fd));
        ASSERT_TRUE(s != nullptr);
    });

    WaitForFdeventLoop();
    EXPECT_EQ(1u + GetAdditionalLocalSocketCount(), fdevent_installed_count());

    // Wait until the client closes its socket.
    client_thread.join();

    WaitForFdeventLoop();
    ASSERT_EQ(GetAdditionalLocalSocketCount(), fdevent_installed_count());
    TerminateThread();
}

#endif  // defined(__linux__)

#if ADB_HOST

#define VerifyParseHostServiceFailed(s)                                         \
    do {                                                                        \
        std::string service(s);                                                 \
        std::string_view serial, command;                                       \
        bool result = internal::parse_host_service(&serial, &command, service); \
        EXPECT_FALSE(result);                                                   \
    } while (0)

#define VerifyParseHostService(s, expected_serial, expected_command)            \
    do {                                                                        \
        std::string service(s);                                                 \
        std::string_view serial, command;                                       \
        bool result = internal::parse_host_service(&serial, &command, service); \
        EXPECT_TRUE(result);                                                    \
        EXPECT_EQ(std::string(expected_serial), std::string(serial));           \
        EXPECT_EQ(std::string(expected_command), std::string(command));         \
    } while (0);

// Check [tcp:|udp:]<serial>[:<port>]:<command> format.
TEST(socket_test, test_parse_host_service) {
    for (const std::string& protocol : {"", "tcp:", "udp:"}) {
        VerifyParseHostServiceFailed(protocol);
        VerifyParseHostServiceFailed(protocol + "foo");

        {
            std::string serial = protocol + "foo";
            VerifyParseHostService(serial + ":bar", serial, "bar");
            VerifyParseHostService(serial + " :bar:baz", serial, "bar:baz");
        }

        {
            // With port.
            std::string serial = protocol + "foo:123";
            VerifyParseHostService(serial + ":bar", serial, "bar");
            VerifyParseHostService(serial + ":456", serial, "456");
            VerifyParseHostService(serial + ":bar:baz", serial, "bar:baz");
        }

        // Don't register a port unless it's all numbers and ends with ':'.
        VerifyParseHostService(protocol + "foo:123", protocol + "foo", "123");
        VerifyParseHostService(protocol + "foo:123bar:baz", protocol + "foo", "123bar:baz");

        std::string addresses[] = {"100.100.100.100", "[0123:4567:89ab:CDEF:0:9:a:f]", "[::1]"};
        for (const std::string& address : addresses) {
            std::string serial = protocol + address;
            std::string serial_with_port = protocol + address + ":5555";
            VerifyParseHostService(serial + ":foo", serial, "foo");
            VerifyParseHostService(serial_with_port + ":foo", serial_with_port, "foo");
        }

        // If we can't find both [] then treat it as a normal serial with [ in it.
        VerifyParseHostService(protocol + "[0123:foo", protocol + "[0123", "foo");

        // Don't be fooled by random IPv6 addresses in the command string.
        VerifyParseHostService(protocol + "foo:ping [0123:4567:89ab:CDEF:0:9:a:f]:5555",
                               protocol + "foo", "ping [0123:4567:89ab:CDEF:0:9:a:f]:5555");

        // Handle embedded NULs properly.
        VerifyParseHostService(protocol + "foo:echo foo\0bar"s, protocol + "foo",
                               "echo foo\0bar"sv);
    }
}

// Check <prefix>:<serial>:<command> format.
TEST(socket_test, test_parse_host_service_prefix) {
    for (const std::string& prefix : {"usb:", "product:", "model:", "device:"}) {
        VerifyParseHostServiceFailed(prefix);
        VerifyParseHostServiceFailed(prefix + "foo");

        VerifyParseHostService(prefix + "foo:bar", prefix + "foo", "bar");
        VerifyParseHostService(prefix + "foo:bar:baz", prefix + "foo", "bar:baz");
        VerifyParseHostService(prefix + "foo:123:bar", prefix + "foo", "123:bar");
    }
}

#endif  // ADB_HOST

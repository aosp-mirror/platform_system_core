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

struct ThreadArg {
    int first_read_fd;
    int last_write_fd;
    size_t middle_pipe_count;
};

class LocalSocketTest : public FdeventTest {};

constexpr auto SLEEP_FOR_FDEVENT = 100ms;

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
    asocket* prev_tail = create_local_socket(first[1]);
    ASSERT_NE(nullptr, prev_tail);

    auto connect = [](asocket* tail, asocket* head) {
        tail->peer = head;
        head->peer = tail;
        tail->ready(tail);
    };

    for (auto& intermediate : intermediates) {
        ASSERT_EQ(0, adb_socketpair(intermediate.data())) << strerror(errno);

        asocket* head = create_local_socket(intermediate[0]);
        ASSERT_NE(nullptr, head);

        asocket* tail = create_local_socket(intermediate[1]);
        ASSERT_NE(nullptr, tail);

        connect(prev_tail, head);
        prev_tail = tail;
    }

    asocket* end = create_local_socket(last[0]);
    ASSERT_NE(nullptr, end);
    connect(prev_tail, end);

    PrepareThread();
    std::thread thread(fdevent_loop);

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
    std::this_thread::sleep_for(SLEEP_FOR_FDEVENT);
    ASSERT_EQ(GetAdditionalLocalSocketCount(), fdevent_installed_count());
    TerminateThread(thread);
}

struct CloseWithPacketArg {
    int socket_fd;
    size_t bytes_written;
    int cause_close_fd;
};

static void CloseWithPacketThreadFunc(CloseWithPacketArg* arg) {
    asocket* s = create_local_socket(arg->socket_fd);
    ASSERT_TRUE(s != nullptr);
    arg->bytes_written = 0;
    while (true) {
        apacket* p = get_apacket();
        p->len = sizeof(p->data);
        arg->bytes_written += p->len;
        int ret = s->enqueue(s, p);
        if (ret == 1) {
            // The writer has one packet waiting to send.
            break;
        }
    }

    asocket* cause_close_s = create_local_socket(arg->cause_close_fd);
    ASSERT_TRUE(cause_close_s != nullptr);
    cause_close_s->peer = s;
    s->peer = cause_close_s;
    cause_close_s->ready(cause_close_s);

    fdevent_loop();
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
    arg.socket_fd = socket_fd[1];
    arg.cause_close_fd = cause_close_fd[1];

    PrepareThread();
    std::thread thread(CloseWithPacketThreadFunc, &arg);
    // Wait until the fdevent_loop() starts.
    std::this_thread::sleep_for(SLEEP_FOR_FDEVENT);
    ASSERT_EQ(0, adb_close(cause_close_fd[0]));
    std::this_thread::sleep_for(SLEEP_FOR_FDEVENT);
    EXPECT_EQ(1u + GetAdditionalLocalSocketCount(), fdevent_installed_count());
    ASSERT_EQ(0, adb_close(socket_fd[0]));
    std::this_thread::sleep_for(SLEEP_FOR_FDEVENT);
    ASSERT_EQ(GetAdditionalLocalSocketCount(), fdevent_installed_count());
    TerminateThread(thread);
}

// This test checks if we can read packets from a closing local socket.
TEST_F(LocalSocketTest, read_from_closing_socket) {
    int socket_fd[2];
    ASSERT_EQ(0, adb_socketpair(socket_fd));
    int cause_close_fd[2];
    ASSERT_EQ(0, adb_socketpair(cause_close_fd));
    CloseWithPacketArg arg;
    arg.socket_fd = socket_fd[1];
    arg.cause_close_fd = cause_close_fd[1];

    PrepareThread();
    std::thread thread(CloseWithPacketThreadFunc, &arg);
    // Wait until the fdevent_loop() starts.
    std::this_thread::sleep_for(SLEEP_FOR_FDEVENT);
    ASSERT_EQ(0, adb_close(cause_close_fd[0]));
    std::this_thread::sleep_for(SLEEP_FOR_FDEVENT);
    EXPECT_EQ(1u + GetAdditionalLocalSocketCount(), fdevent_installed_count());

    // Verify if we can read successfully.
    std::vector<char> buf(arg.bytes_written);
    ASSERT_NE(0u, arg.bytes_written);
    ASSERT_EQ(true, ReadFdExactly(socket_fd[0], buf.data(), buf.size()));
    ASSERT_EQ(0, adb_close(socket_fd[0]));

    std::this_thread::sleep_for(SLEEP_FOR_FDEVENT);
    ASSERT_EQ(GetAdditionalLocalSocketCount(), fdevent_installed_count());
    TerminateThread(thread);
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
    arg.socket_fd = socket_fd[1];
    arg.cause_close_fd = cause_close_fd[1];

    PrepareThread();
    std::thread thread(CloseWithPacketThreadFunc, &arg);
    // Wait until the fdevent_loop() starts.
    std::this_thread::sleep_for(SLEEP_FOR_FDEVENT);
    EXPECT_EQ(2u + GetAdditionalLocalSocketCount(), fdevent_installed_count());
    ASSERT_EQ(0, adb_close(socket_fd[0]));

    std::this_thread::sleep_for(SLEEP_FOR_FDEVENT);
    ASSERT_EQ(GetAdditionalLocalSocketCount(), fdevent_installed_count());
    TerminateThread(thread);
}

#if defined(__linux__)

static void ClientThreadFunc() {
    std::string error;
    int fd = network_loopback_client(5038, SOCK_STREAM, &error);
    ASSERT_GE(fd, 0) << error;
    std::this_thread::sleep_for(200ms);
    ASSERT_EQ(0, adb_close(fd));
}

struct CloseRdHupSocketArg {
    int socket_fd;
};

static void CloseRdHupSocketThreadFunc(CloseRdHupSocketArg* arg) {
    asocket* s = create_local_socket(arg->socket_fd);
    ASSERT_TRUE(s != nullptr);

    fdevent_loop();
}

// This test checks if we can close sockets in CLOSE_WAIT state.
TEST_F(LocalSocketTest, close_socket_in_CLOSE_WAIT_state) {
    std::string error;
    int listen_fd = network_inaddr_any_server(5038, SOCK_STREAM, &error);
    ASSERT_GE(listen_fd, 0);

    std::thread client_thread(ClientThreadFunc);

    int accept_fd = adb_socket_accept(listen_fd, nullptr, nullptr);
    ASSERT_GE(accept_fd, 0);
    CloseRdHupSocketArg arg;
    arg.socket_fd = accept_fd;

    PrepareThread();
    std::thread thread(CloseRdHupSocketThreadFunc, &arg);

    // Wait until the fdevent_loop() starts.
    std::this_thread::sleep_for(SLEEP_FOR_FDEVENT);
    EXPECT_EQ(1u + GetAdditionalLocalSocketCount(), fdevent_installed_count());

    // Wait until the client closes its socket.
    client_thread.join();

    std::this_thread::sleep_for(SLEEP_FOR_FDEVENT);
    ASSERT_EQ(GetAdditionalLocalSocketCount(), fdevent_installed_count());
    TerminateThread(thread);
}

#endif  // defined(__linux__)

#if ADB_HOST

// Checks that skip_host_serial(serial) returns a pointer to the part of |serial| which matches
// |expected|, otherwise logs the failure to gtest.
void VerifySkipHostSerial(std::string serial, const char* expected) {
    char* result = internal::skip_host_serial(&serial[0]);
    if (expected == nullptr) {
        EXPECT_EQ(nullptr, result);
    } else {
        EXPECT_STREQ(expected, result);
    }
}

// Check [tcp:|udp:]<serial>[:<port>]:<command> format.
TEST(socket_test, test_skip_host_serial) {
    for (const std::string& protocol : {"", "tcp:", "udp:"}) {
        VerifySkipHostSerial(protocol, nullptr);
        VerifySkipHostSerial(protocol + "foo", nullptr);

        VerifySkipHostSerial(protocol + "foo:bar", ":bar");
        VerifySkipHostSerial(protocol + "foo:bar:baz", ":bar:baz");

        VerifySkipHostSerial(protocol + "foo:123:bar", ":bar");
        VerifySkipHostSerial(protocol + "foo:123:456", ":456");
        VerifySkipHostSerial(protocol + "foo:123:bar:baz", ":bar:baz");

        // Don't register a port unless it's all numbers and ends with ':'.
        VerifySkipHostSerial(protocol + "foo:123", ":123");
        VerifySkipHostSerial(protocol + "foo:123bar:baz", ":123bar:baz");

        VerifySkipHostSerial(protocol + "100.100.100.100:5555:foo", ":foo");
        VerifySkipHostSerial(protocol + "[0123:4567:89ab:CDEF:0:9:a:f]:5555:foo", ":foo");
        VerifySkipHostSerial(protocol + "[::1]:5555:foo", ":foo");

        // If we can't find both [] then treat it as a normal serial with [ in it.
        VerifySkipHostSerial(protocol + "[0123:foo", ":foo");

        // Don't be fooled by random IPv6 addresses in the command string.
        VerifySkipHostSerial(protocol + "foo:ping [0123:4567:89ab:CDEF:0:9:a:f]:5555",
                             ":ping [0123:4567:89ab:CDEF:0:9:a:f]:5555");
    }
}

// Check <prefix>:<serial>:<command> format.
TEST(socket_test, test_skip_host_serial_prefix) {
    for (const std::string& prefix : {"usb:", "product:", "model:", "device:"}) {
        VerifySkipHostSerial(prefix, nullptr);
        VerifySkipHostSerial(prefix + "foo", nullptr);

        VerifySkipHostSerial(prefix + "foo:bar", ":bar");
        VerifySkipHostSerial(prefix + "foo:bar:baz", ":bar:baz");
        VerifySkipHostSerial(prefix + "foo:123:bar", ":123:bar");
    }
}

#endif  // ADB_HOST

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

#include <limits>
#include <queue>
#include <string>
#include <vector>

#include <pthread.h>
#include <signal.h>
#include <unistd.h>

#include "adb.h"
#include "adb_io.h"
#include "socket.h"
#include "sysdeps.h"

static void signal_handler(int) {
    ASSERT_EQ(1u, fdevent_installed_count());
    pthread_exit(nullptr);
}

// On host, register a dummy socket, so fdevet_loop() will not abort when previously
// registered local sockets are all closed. On device, fdevent_subproc_setup() installs
// one fdevent which can be considered as dummy socket.
static void InstallDummySocket() {
#if ADB_HOST
    int dummy_fds[2];
    ASSERT_EQ(0, pipe(dummy_fds));
    asocket* dummy_socket = create_local_socket(dummy_fds[0]);
    ASSERT_TRUE(dummy_socket != nullptr);
    dummy_socket->ready(dummy_socket);
#endif
}

struct ThreadArg {
    int first_read_fd;
    int last_write_fd;
    size_t middle_pipe_count;
};

static void FdEventThreadFunc(ThreadArg* arg) {
    std::vector<int> read_fds;
    std::vector<int> write_fds;

    read_fds.push_back(arg->first_read_fd);
    for (size_t i = 0; i < arg->middle_pipe_count; ++i) {
        int fds[2];
        ASSERT_EQ(0, adb_socketpair(fds));
        read_fds.push_back(fds[0]);
        write_fds.push_back(fds[1]);
    }
    write_fds.push_back(arg->last_write_fd);

    for (size_t i = 0; i < read_fds.size(); ++i) {
        asocket* reader = create_local_socket(read_fds[i]);
        ASSERT_TRUE(reader != nullptr);
        asocket* writer = create_local_socket(write_fds[i]);
        ASSERT_TRUE(writer != nullptr);
        reader->peer = writer;
        writer->peer = reader;
        reader->ready(reader);
    }

    InstallDummySocket();
    fdevent_loop();
}

class LocalSocketTest : public ::testing::Test {
  protected:
    static void SetUpTestCase() {
        ASSERT_NE(SIG_ERR, signal(SIGUSR1, signal_handler));
        ASSERT_NE(SIG_ERR, signal(SIGPIPE, SIG_IGN));
    }

    virtual void SetUp() {
        fdevent_reset();
        ASSERT_EQ(0u, fdevent_installed_count());
    }
};

TEST_F(LocalSocketTest, smoke) {
    const size_t PIPE_COUNT = 100;
    const size_t MESSAGE_LOOP_COUNT = 100;
    const std::string MESSAGE = "socket_test";
    int fd_pair1[2];
    int fd_pair2[2];
    ASSERT_EQ(0, adb_socketpair(fd_pair1));
    ASSERT_EQ(0, adb_socketpair(fd_pair2));
    pthread_t thread;
    ThreadArg thread_arg;
    thread_arg.first_read_fd = fd_pair1[0];
    thread_arg.last_write_fd = fd_pair2[1];
    thread_arg.middle_pipe_count = PIPE_COUNT;
    int writer = fd_pair1[1];
    int reader = fd_pair2[0];

    ASSERT_EQ(0, pthread_create(&thread, nullptr,
                                reinterpret_cast<void* (*)(void*)>(FdEventThreadFunc),
                                &thread_arg));

    usleep(1000);
    for (size_t i = 0; i < MESSAGE_LOOP_COUNT; ++i) {
        std::string read_buffer = MESSAGE;
        std::string write_buffer(MESSAGE.size(), 'a');
        ASSERT_TRUE(WriteFdExactly(writer, read_buffer.c_str(), read_buffer.size()));
        ASSERT_TRUE(ReadFdExactly(reader, &write_buffer[0], write_buffer.size()));
        ASSERT_EQ(read_buffer, write_buffer);
    }
    ASSERT_EQ(0, adb_close(writer));
    ASSERT_EQ(0, adb_close(reader));
    // Wait until the local sockets are closed.
    sleep(1);

    ASSERT_EQ(0, pthread_kill(thread, SIGUSR1));
    ASSERT_EQ(0, pthread_join(thread, nullptr));
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

    InstallDummySocket();
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
    pthread_t thread;
    ASSERT_EQ(0, pthread_create(&thread, nullptr,
                                reinterpret_cast<void* (*)(void*)>(CloseWithPacketThreadFunc),
                                &arg));
    // Wait until the fdevent_loop() starts.
    sleep(1);
    ASSERT_EQ(0, adb_close(cause_close_fd[0]));
    sleep(1);
    ASSERT_EQ(2u, fdevent_installed_count());
    ASSERT_EQ(0, adb_close(socket_fd[0]));
    // Wait until the socket is closed.
    sleep(1);

    ASSERT_EQ(0, pthread_kill(thread, SIGUSR1));
    ASSERT_EQ(0, pthread_join(thread, nullptr));
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

    pthread_t thread;
    ASSERT_EQ(0, pthread_create(&thread, nullptr,
                                reinterpret_cast<void* (*)(void*)>(CloseWithPacketThreadFunc),
                                &arg));
    // Wait until the fdevent_loop() starts.
    sleep(1);
    ASSERT_EQ(0, adb_close(cause_close_fd[0]));
    sleep(1);
    ASSERT_EQ(2u, fdevent_installed_count());

    // Verify if we can read successfully.
    std::vector<char> buf(arg.bytes_written);
    ASSERT_EQ(true, ReadFdExactly(socket_fd[0], buf.data(), buf.size()));
    ASSERT_EQ(0, adb_close(socket_fd[0]));

    // Wait until the socket is closed.
    sleep(1);

    ASSERT_EQ(0, pthread_kill(thread, SIGUSR1));
    ASSERT_EQ(0, pthread_join(thread, nullptr));
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

    pthread_t thread;
    ASSERT_EQ(0, pthread_create(&thread, nullptr,
                                reinterpret_cast<void* (*)(void*)>(CloseWithPacketThreadFunc),
                                &arg));
    // Wait until the fdevent_loop() starts.
    sleep(1);
    ASSERT_EQ(3u, fdevent_installed_count());
    ASSERT_EQ(0, adb_close(socket_fd[0]));

    // Wait until the socket is closed.
    sleep(1);

    ASSERT_EQ(0, pthread_kill(thread, SIGUSR1));
    ASSERT_EQ(0, pthread_join(thread, nullptr));
}

#if defined(__linux__)

static void ClientThreadFunc() {
    std::string error;
    int fd = network_loopback_client(5038, SOCK_STREAM, &error);
    ASSERT_GE(fd, 0) << error;
    sleep(2);
    ASSERT_EQ(0, adb_close(fd));
}

struct CloseRdHupSocketArg {
  int socket_fd;
};

static void CloseRdHupSocketThreadFunc(CloseRdHupSocketArg* arg) {
  asocket* s = create_local_socket(arg->socket_fd);
  ASSERT_TRUE(s != nullptr);

  InstallDummySocket();
  fdevent_loop();
}

// This test checks if we can close sockets in CLOSE_WAIT state.
TEST_F(LocalSocketTest, close_socket_in_CLOSE_WAIT_state) {
  std::string error;
  int listen_fd = network_inaddr_any_server(5038, SOCK_STREAM, &error);
  ASSERT_GE(listen_fd, 0);
  pthread_t client_thread;
  ASSERT_EQ(0, pthread_create(&client_thread, nullptr,
                              reinterpret_cast<void* (*)(void*)>(ClientThreadFunc), nullptr));

  struct sockaddr addr;
  socklen_t alen;
  alen = sizeof(addr);
  int accept_fd = adb_socket_accept(listen_fd, &addr, &alen);
  ASSERT_GE(accept_fd, 0);
  CloseRdHupSocketArg arg;
  arg.socket_fd = accept_fd;
  pthread_t thread;
  ASSERT_EQ(0, pthread_create(&thread, nullptr,
                              reinterpret_cast<void* (*)(void*)>(CloseRdHupSocketThreadFunc),
                              &arg));
  // Wait until the fdevent_loop() starts.
  sleep(1);
  ASSERT_EQ(2u, fdevent_installed_count());
  // Wait until the client closes its socket.
  ASSERT_EQ(0, pthread_join(client_thread, nullptr));
  sleep(2);
  ASSERT_EQ(0, pthread_kill(thread, SIGUSR1));
  ASSERT_EQ(0, pthread_join(thread, nullptr));
}

#endif  // defined(__linux__)

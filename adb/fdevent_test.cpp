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
#include <thread>
#include <vector>

#include "adb_io.h"
#include "fdevent_test.h"

class FdHandler {
  public:
    FdHandler(int read_fd, int write_fd) : read_fd_(read_fd), write_fd_(write_fd) {
        fdevent_install(&read_fde_, read_fd_, FdEventCallback, this);
        fdevent_add(&read_fde_, FDE_READ);
        fdevent_install(&write_fde_, write_fd_, FdEventCallback, this);
    }

    ~FdHandler() {
        fdevent_remove(&read_fde_);
        fdevent_remove(&write_fde_);
    }

  private:
    static void FdEventCallback(int fd, unsigned events, void* userdata) {
        FdHandler* handler = reinterpret_cast<FdHandler*>(userdata);
        ASSERT_EQ(0u, (events & ~(FDE_READ | FDE_WRITE))) << "unexpected events: " << events;
        if (events & FDE_READ) {
            ASSERT_EQ(fd, handler->read_fd_);
            char c;
            ASSERT_EQ(1, adb_read(fd, &c, 1));
            handler->queue_.push(c);
            fdevent_add(&handler->write_fde_, FDE_WRITE);
        }
        if (events & FDE_WRITE) {
            ASSERT_EQ(fd, handler->write_fd_);
            ASSERT_FALSE(handler->queue_.empty());
            char c = handler->queue_.front();
            handler->queue_.pop();
            ASSERT_EQ(1, adb_write(fd, &c, 1));
            if (handler->queue_.empty()) {
              fdevent_del(&handler->write_fde_, FDE_WRITE);
            }
        }
    }

  private:
    const int read_fd_;
    const int write_fd_;
    fdevent read_fde_;
    fdevent write_fde_;
    std::queue<char> queue_;
};

struct ThreadArg {
    int first_read_fd;
    int last_write_fd;
    size_t middle_pipe_count;
};

TEST_F(FdeventTest, fdevent_terminate) {
    PrepareThread();

    std::thread thread(fdevent_loop);
    TerminateThread(thread);
}

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

    std::vector<std::unique_ptr<FdHandler>> fd_handlers;
    for (size_t i = 0; i < read_fds.size(); ++i) {
        fd_handlers.push_back(std::unique_ptr<FdHandler>(new FdHandler(read_fds[i], write_fds[i])));
    }

    fdevent_loop();
}

TEST_F(FdeventTest, smoke) {
    const size_t PIPE_COUNT = 10;
    const size_t MESSAGE_LOOP_COUNT = 100;
    const std::string MESSAGE = "fdevent_test";
    int fd_pair1[2];
    int fd_pair2[2];
    ASSERT_EQ(0, adb_socketpair(fd_pair1));
    ASSERT_EQ(0, adb_socketpair(fd_pair2));
    ThreadArg thread_arg;
    thread_arg.first_read_fd = fd_pair1[0];
    thread_arg.last_write_fd = fd_pair2[1];
    thread_arg.middle_pipe_count = PIPE_COUNT;
    int writer = fd_pair1[1];
    int reader = fd_pair2[0];

    PrepareThread();
    std::thread thread(FdEventThreadFunc, &thread_arg);

    for (size_t i = 0; i < MESSAGE_LOOP_COUNT; ++i) {
        std::string read_buffer = MESSAGE;
        std::string write_buffer(MESSAGE.size(), 'a');
        ASSERT_TRUE(WriteFdExactly(writer, read_buffer.c_str(), read_buffer.size()));
        ASSERT_TRUE(ReadFdExactly(reader, &write_buffer[0], write_buffer.size()));
        ASSERT_EQ(read_buffer, write_buffer);
    }

    TerminateThread(thread);
    ASSERT_EQ(0, adb_close(writer));
    ASSERT_EQ(0, adb_close(reader));
}

struct InvalidFdArg {
    fdevent fde;
    unsigned expected_events;
    size_t* happened_event_count;
};

static void InvalidFdEventCallback(int fd, unsigned events, void* userdata) {
    InvalidFdArg* arg = reinterpret_cast<InvalidFdArg*>(userdata);
    ASSERT_EQ(arg->expected_events, events);
    fdevent_remove(&arg->fde);
    if (++*(arg->happened_event_count) == 2) {
        fdevent_terminate_loop();
    }
}

static void InvalidFdThreadFunc() {
    const int INVALID_READ_FD = std::numeric_limits<int>::max() - 1;
    size_t happened_event_count = 0;
    InvalidFdArg read_arg;
    read_arg.expected_events = FDE_READ | FDE_ERROR;
    read_arg.happened_event_count = &happened_event_count;
    fdevent_install(&read_arg.fde, INVALID_READ_FD, InvalidFdEventCallback, &read_arg);
    fdevent_add(&read_arg.fde, FDE_READ);

    const int INVALID_WRITE_FD = std::numeric_limits<int>::max();
    InvalidFdArg write_arg;
    write_arg.expected_events = FDE_READ | FDE_ERROR;
    write_arg.happened_event_count = &happened_event_count;
    fdevent_install(&write_arg.fde, INVALID_WRITE_FD, InvalidFdEventCallback, &write_arg);
    fdevent_add(&write_arg.fde, FDE_WRITE);
    fdevent_loop();
}

TEST_F(FdeventTest, invalid_fd) {
    std::thread thread(InvalidFdThreadFunc);
    thread.join();
}

TEST_F(FdeventTest, run_on_main_thread) {
    std::vector<int> vec;

    PrepareThread();
    std::thread thread(fdevent_loop);

    for (int i = 0; i < 100; ++i) {
        fdevent_run_on_main_thread([i, &vec]() {
            check_main_thread();
            vec.push_back(i);
        });
    }

    TerminateThread(thread);

    ASSERT_EQ(100u, vec.size());
    for (int i = 0; i < 100; ++i) {
        ASSERT_EQ(i, vec[i]);
    }
}

static std::function<void()> make_appender(std::vector<int>* vec, int value) {
    return [vec, value]() {
        check_main_thread();
        if (value == 100) {
            return;
        }

        vec->push_back(value);
        fdevent_run_on_main_thread(make_appender(vec, value + 1));
    };
}

TEST_F(FdeventTest, run_on_main_thread_reentrant) {
    std::vector<int> vec;

    PrepareThread();
    std::thread thread(fdevent_loop);

    fdevent_run_on_main_thread(make_appender(&vec, 0));

    TerminateThread(thread);

    ASSERT_EQ(100u, vec.size());
    for (int i = 0; i < 100; ++i) {
        ASSERT_EQ(i, vec[i]);
    }
}

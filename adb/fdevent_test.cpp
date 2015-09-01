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

#include <queue>
#include <string>
#include <vector>

#include <pthread.h>
#include <signal.h>

#include "adb_io.h"

class SignalHandlerRegister {
  public:
    SignalHandlerRegister(const std::vector<int>& signums, void (*handler)(int)) {
        for (auto& sig : signums) {
            sig_t old_handler = signal(sig, handler);
            saved_signal_handlers_.push_back(std::make_pair(sig, old_handler));
        }
    }

    ~SignalHandlerRegister() {
        for (auto& pair : saved_signal_handlers_) {
            signal(pair.first, pair.second);
        }
    }

  private:
    std::vector<std::pair<int, sig_t>> saved_signal_handlers_;
};

class FdHandler {
  public:
    FdHandler(int read_fd, int write_fd) : read_fd_(read_fd), write_fd_(write_fd) {
        fdevent_install(&read_fde_, read_fd_, FdEventCallback, this);
        fdevent_add(&read_fde_, FDE_READ | FDE_ERROR);
        fdevent_install(&write_fde_, write_fd_, FdEventCallback, this);
        fdevent_add(&write_fde_, FDE_ERROR);
    }

  private:
    static void FdEventCallback(int fd, unsigned events, void* userdata) {
        FdHandler* handler = reinterpret_cast<FdHandler*>(userdata);
        ASSERT_EQ(0u, (events & ~(FDE_READ | FDE_WRITE))) << "unexpected events: " << events;
        if (events & FDE_READ) {
            ASSERT_EQ(fd, handler->read_fd_);
            char c;
            ASSERT_EQ(1, read(fd, &c, 1));
            handler->queue_.push(c);
            fdevent_add(&handler->write_fde_, FDE_WRITE);
        }
        if (events & FDE_WRITE) {
            ASSERT_EQ(fd, handler->write_fd_);
            ASSERT_FALSE(handler->queue_.empty());
            char c = handler->queue_.front();
            handler->queue_.pop();
            ASSERT_EQ(1, write(fd, &c, 1));
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

static void signal_handler(int) {
    pthread_exit(nullptr);
}

struct ThreadArg {
    int first_read_fd;
    int last_write_fd;
    size_t middle_pipe_count;
};

static void FdEventThreadFunc(ThreadArg* arg) {
    SignalHandlerRegister signal_handler_register({SIGUSR1}, signal_handler);

    std::vector<int> read_fds;
    std::vector<int> write_fds;

    read_fds.push_back(arg->first_read_fd);
    for (size_t i = 0; i < arg->middle_pipe_count; ++i) {
        int fds[2];
        ASSERT_EQ(0, pipe(fds));
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

TEST(fdevent, smoke) {
    const size_t PIPE_COUNT = 10;
    const size_t MESSAGE_LOOP_COUNT = 100;
    const std::string MESSAGE = "fdevent_test";
    int fd_pair1[2];
    int fd_pair2[2];
    ASSERT_EQ(0, pipe(fd_pair1));
    ASSERT_EQ(0, pipe(fd_pair2));
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

    for (size_t i = 0; i < MESSAGE_LOOP_COUNT; ++i) {
        std::string read_buffer = MESSAGE;
        std::string write_buffer(MESSAGE.size(), 'a');
        ASSERT_TRUE(WriteFdExactly(writer, read_buffer.c_str(), read_buffer.size()));
        ASSERT_TRUE(ReadFdExactly(reader, &write_buffer[0], write_buffer.size()));
        ASSERT_EQ(read_buffer, write_buffer);
    }

    ASSERT_EQ(0, pthread_kill(thread, SIGUSR1));
    ASSERT_EQ(0, pthread_join(thread, nullptr));
}

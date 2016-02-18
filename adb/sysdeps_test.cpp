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

#include <gtest/gtest.h>
#include <unistd.h>
#include <atomic>

#include "adb_io.h"
#include "sysdeps.h"

static void increment_atomic_int(void* c) {
    sleep(1);
    reinterpret_cast<std::atomic<int>*>(c)->fetch_add(1);
}

TEST(sysdeps_thread, smoke) {
    std::atomic<int> counter(0);

    for (int i = 0; i < 100; ++i) {
        ASSERT_TRUE(adb_thread_create(increment_atomic_int, &counter));
    }

    sleep(2);
    ASSERT_EQ(100, counter.load());
}

TEST(sysdeps_thread, join) {
    std::atomic<int> counter(0);
    std::vector<adb_thread_t> threads(500);
    for (size_t i = 0; i < threads.size(); ++i) {
        ASSERT_TRUE(adb_thread_create(increment_atomic_int, &counter, &threads[i]));
    }

    int current = counter.load();
    ASSERT_GE(current, 0);
    // Make sure that adb_thread_create actually creates threads, and doesn't do something silly
    // like synchronously run the function passed in. The sleep in increment_atomic_int should be
    // enough to keep this from being flakey.
    ASSERT_LT(current, 500);

    for (const auto& thread : threads) {
        ASSERT_TRUE(adb_thread_join(thread));
    }

    ASSERT_EQ(500, counter.load());
}

TEST(sysdeps_thread, exit) {
    adb_thread_t thread;
    ASSERT_TRUE(adb_thread_create(
        [](void*) {
            adb_thread_exit();
            for (;;) continue;
        },
        nullptr, &thread));
    ASSERT_TRUE(adb_thread_join(thread));
}

TEST(sysdeps_socketpair, smoke) {
    int fds[2];
    ASSERT_EQ(0, adb_socketpair(fds)) << strerror(errno);
    ASSERT_TRUE(WriteFdExactly(fds[0], "foo", 4));
    ASSERT_TRUE(WriteFdExactly(fds[1], "bar", 4));

    char buf[4];
    ASSERT_TRUE(ReadFdExactly(fds[1], buf, 4));
    ASSERT_STREQ(buf, "foo");
    ASSERT_TRUE(ReadFdExactly(fds[0], buf, 4));
    ASSERT_STREQ(buf, "bar");
    ASSERT_EQ(0, adb_close(fds[0]));
    ASSERT_EQ(0, adb_close(fds[1]));
}

TEST(sysdeps_fd, exhaustion) {
    std::vector<int> fds;
    int socketpair[2];

    while (adb_socketpair(socketpair) == 0) {
        fds.push_back(socketpair[0]);
        fds.push_back(socketpair[1]);
    }

    ASSERT_EQ(EMFILE, errno) << strerror(errno);
    for (int fd : fds) {
        ASSERT_EQ(0, adb_close(fd));
    }
    ASSERT_EQ(0, adb_socketpair(socketpair));
    ASSERT_EQ(socketpair[0], fds[0]);
    ASSERT_EQ(socketpair[1], fds[1]);
    ASSERT_EQ(0, adb_close(socketpair[0]));
    ASSERT_EQ(0, adb_close(socketpair[1]));
}

class sysdeps_poll : public ::testing::Test {
  protected:
    int fds[2];
    void SetUp() override {
        ASSERT_EQ(0, adb_socketpair(fds)) << strerror(errno);
    }

    void TearDown() override {
        ASSERT_EQ(0, adb_close(fds[0]));
        ASSERT_EQ(0, adb_close(fds[1]));
    }
};

TEST_F(sysdeps_poll, smoke) {
    adb_pollfd pfd[2];
    pfd[0].fd = fds[0];
    pfd[0].events = POLLRDNORM;
    pfd[1].fd = fds[1];
    pfd[1].events = POLLWRNORM;

    EXPECT_EQ(1, adb_poll(pfd, 2, 0));
    EXPECT_EQ(0, pfd[0].revents);
    EXPECT_EQ(POLLWRNORM, pfd[1].revents);

    ASSERT_TRUE(WriteFdExactly(fds[1], "foo", 4));

    // Wait for the socketpair to be flushed.
    EXPECT_EQ(1, adb_poll(pfd, 1, 100));
    EXPECT_EQ(POLLRDNORM, pfd[0].revents);

    EXPECT_EQ(2, adb_poll(pfd, 2, 0));
    EXPECT_EQ(POLLRDNORM, pfd[0].revents);
    EXPECT_EQ(POLLWRNORM, pfd[1].revents);
}

TEST_F(sysdeps_poll, timeout) {
    adb_pollfd pfd;
    pfd.fd = fds[0];
    pfd.events = POLLRDNORM;

    EXPECT_EQ(0, adb_poll(&pfd, 1, 100));
    EXPECT_EQ(0, pfd.revents);

    ASSERT_TRUE(WriteFdExactly(fds[1], "foo", 4));

    EXPECT_EQ(1, adb_poll(&pfd, 1, 100));
    EXPECT_EQ(POLLRDNORM, pfd.revents);
}

TEST_F(sysdeps_poll, invalid_fd) {
    adb_pollfd pfd[3];
    pfd[0].fd = fds[0];
    pfd[0].events = POLLRDNORM;
    pfd[1].fd = INT_MAX;
    pfd[1].events = POLLRDNORM;
    pfd[2].fd = fds[1];
    pfd[2].events = POLLWRNORM;

    ASSERT_TRUE(WriteFdExactly(fds[1], "foo", 4));

    // Wait for the socketpair to be flushed.
    EXPECT_EQ(1, adb_poll(pfd, 1, 100));
    EXPECT_EQ(POLLRDNORM, pfd[0].revents);

    EXPECT_EQ(3, adb_poll(pfd, 3, 0));
    EXPECT_EQ(POLLRDNORM, pfd[0].revents);
    EXPECT_EQ(POLLNVAL, pfd[1].revents);
    EXPECT_EQ(POLLWRNORM, pfd[2].revents);
}

TEST_F(sysdeps_poll, duplicate_fd) {
    adb_pollfd pfd[2];
    pfd[0].fd = fds[0];
    pfd[0].events = POLLRDNORM;
    pfd[1] = pfd[0];

    EXPECT_EQ(0, adb_poll(pfd, 2, 0));
    EXPECT_EQ(0, pfd[0].revents);
    EXPECT_EQ(0, pfd[1].revents);

    ASSERT_TRUE(WriteFdExactly(fds[1], "foo", 4));

    EXPECT_EQ(2, adb_poll(pfd, 2, 100));
    EXPECT_EQ(POLLRDNORM, pfd[0].revents);
    EXPECT_EQ(POLLRDNORM, pfd[1].revents);
}

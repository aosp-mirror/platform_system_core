/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include <android-base/unique_fd.h>
#include <binder/IPCThreadState.h>
#include <gtest/gtest.h>
#include <poll.h>
#include <trusty/metrics/metrics.h>
#include <trusty/tipc.h>

#define TIPC_DEV "/dev/trusty-ipc-dev0"
#define CRASHER_PORT "com.android.trusty.metrics.test.crasher"

namespace android {
namespace trusty {
namespace metrics {

using android::base::unique_fd;

static void TriggerCrash() {
    size_t num_retries = 6;
    int fd = -1;

    for (size_t i = 0; i < num_retries; i++) {
        /* It's possible to time out waiting for crasher TA to restart. */
        fd = tipc_connect(TIPC_DEV, CRASHER_PORT);
        if (fd >= 0) {
            break;
        }
    }

    unique_fd crasher(fd);
    ASSERT_GE(crasher, 0);

    int msg = 0;
    int rc = write(crasher, &msg, sizeof(msg));
    ASSERT_EQ(rc, sizeof(msg));
}

class TrustyMetricsTest : public TrustyMetrics, public ::testing::Test {
  public:
    TrustyMetricsTest() : TrustyMetrics(TIPC_DEV) {}

    virtual void HandleCrash(const std::string& app_id) override { crashed_app_ = app_id; }

    virtual void HandleEventDrop() override { event_drop_count_++; }

    virtual void SetUp() override {
        auto ret = Open();
        ASSERT_TRUE(ret.ok()) << ret.error();

        /* Drain events (if any) and reset state */
        DrainEvents();
        crashed_app_.clear();
        event_drop_count_ = 0;
    }

    void DrainEvents() {
        while (WaitForEvent(1000 /* 1 second timeout */).ok()) {
            auto ret = HandleEvent();
            ASSERT_TRUE(ret.ok()) << ret.error();
        }
    }

    void WaitForAndHandleEvent() {
        auto ret = WaitForEvent(30000 /* 30 second timeout */);
        ASSERT_TRUE(ret.ok()) << ret.error();

        ret = HandleEvent();
        ASSERT_TRUE(ret.ok()) << ret.error();
    }

    std::string crashed_app_;
    size_t event_drop_count_;
};

TEST_F(TrustyMetricsTest, Crash) {
    TriggerCrash();
    WaitForAndHandleEvent();

    /* Check that no event was dropped. */
    ASSERT_EQ(event_drop_count_, 0);

    /* Check that correct TA crashed. */
    ASSERT_EQ(crashed_app_, "36f5b435-5bd3-4526-8b76-200e3a7e79f3:crasher");
}

TEST_F(TrustyMetricsTest, PollSet) {
    int binder_fd;
    int rc = IPCThreadState::self()->setupPolling(&binder_fd);
    ASSERT_EQ(rc, 0);
    ASSERT_GE(binder_fd, 0);

    TriggerCrash();

    struct pollfd pfds[] = {
            {
                    .fd = binder_fd,
                    .events = POLLIN,
            },
            {
                    .fd = GetRawFd(),
                    .events = POLLIN,
            },
    };

    rc = poll(pfds, 2, 30000 /* 30 second timeout */);
    /* We expect one event on the metrics fd. */
    ASSERT_EQ(rc, 1);
    ASSERT_TRUE(pfds[1].revents & POLLIN);

    auto ret = HandleEvent();
    ASSERT_TRUE(ret.ok()) << ret.error();

    /* Check that no event was dropped. */
    ASSERT_EQ(event_drop_count_, 0);

    /* Check that correct TA crashed. */
    ASSERT_EQ(crashed_app_, "36f5b435-5bd3-4526-8b76-200e3a7e79f3:crasher");
}

TEST_F(TrustyMetricsTest, EventDrop) {
    /* We know the size of the internal event queue is less than this. */
    size_t num_events = 3;

    ASSERT_EQ(event_drop_count_, 0);

    for (auto i = 0; i < num_events; i++) {
        TriggerCrash();
    }

    for (auto i = 0; i < num_events; i++) {
        WaitForAndHandleEvent();
        if (event_drop_count_ > 0) {
            break;
        }
    }

    ASSERT_EQ(event_drop_count_, 1);
}

}  // namespace metrics
}  // namespace trusty
}  // namespace android

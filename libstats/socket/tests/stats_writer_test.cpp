/*
 * Copyright (C) 2020 The Android Open Source Project
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
#include "stats_buffer_writer.h"
#include "stats_event.h"
#include "stats_socket.h"

TEST(StatsWriterTest, TestSocketClose) {
    AStatsEvent* event = AStatsEvent_obtain();
    AStatsEvent_setAtomId(event, 100);
    AStatsEvent_writeInt32(event, 5);
    int successResult = AStatsEvent_write(event);
    AStatsEvent_release(event);

    // In the case of a successful write, we return the number of bytes written.
    EXPECT_GT(successResult, 0);
    EXPECT_FALSE(stats_log_is_closed());

    AStatsSocket_close();

    EXPECT_TRUE(stats_log_is_closed());
}

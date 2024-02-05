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

#include "../libstatssocket_lazy.h"

#include <gtest/gtest.h>

#include "stats_event.h"
#include "stats_socket.h"

// The tests here are just for the case when libstatssocket.so cannot be loaded by
// libstatssocket_lazy.
class LibstatssocketLazyTest : public ::testing::Test {
  protected:
    virtual void SetUp() {
        ::testing::Test::SetUp();
        PreventLibstatssocketLazyLoadingForTests();
    }
};

static const char* kLoadFailed = "Failed to load libstatssocket.so";

TEST_F(LibstatssocketLazyTest, NoLibstatssocketForStatsEvent) {
    AStatsEvent* event = NULL;
    EXPECT_DEATH(AStatsEvent_obtain(), kLoadFailed);
    EXPECT_DEATH(AStatsEvent_build(event), kLoadFailed);
    EXPECT_DEATH(AStatsEvent_write(event), kLoadFailed);
    EXPECT_DEATH(AStatsEvent_release(event), kLoadFailed);

    EXPECT_DEATH(AStatsEvent_setAtomId(event, 0), kLoadFailed);
    EXPECT_DEATH(AStatsEvent_writeInt32(event, 0), kLoadFailed);
    EXPECT_DEATH(AStatsEvent_writeInt64(event, 0), kLoadFailed);
    EXPECT_DEATH(AStatsEvent_writeFloat(event, 0), kLoadFailed);
    EXPECT_DEATH(AStatsEvent_writeBool(event, false), kLoadFailed);
    EXPECT_DEATH(AStatsEvent_writeByteArray(event, NULL, 0), kLoadFailed);
    EXPECT_DEATH(AStatsEvent_writeString(event, NULL), kLoadFailed);
    EXPECT_DEATH(AStatsEvent_writeStringArray(event, NULL, 0), kLoadFailed);
    EXPECT_DEATH(AStatsEvent_writeAttributionChain(event, NULL, NULL, 0), kLoadFailed);

    EXPECT_DEATH(AStatsEvent_addBoolAnnotation(event, 0, false), kLoadFailed);
    EXPECT_DEATH(AStatsEvent_addInt32Annotation(event, 0, 0), kLoadFailed);
}

TEST_F(LibstatssocketLazyTest, NoLibstatssocketForStatsSocket) {
    EXPECT_DEATH(AStatsSocket_close(), kLoadFailed);
}

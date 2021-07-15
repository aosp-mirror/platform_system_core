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

#include "../libstatspull_lazy.h"

#include <gtest/gtest.h>

#include "stats_pull_atom_callback.h"
//#include "stats_event.h"

// The tests here are just for the case when libstatspull.so cannot be loaded by
// libstatspull_lazy.
class LibstatspullLazyTest : public ::testing::Test {
  protected:
    virtual void SetUp() {
        ::testing::Test::SetUp();
        PreventLibstatspullLazyLoadingForTests();
    }
};

static const char* kLoadFailed = "Failed to load libstatspull.so";

TEST_F(LibstatspullLazyTest, NoLibstatspullForPullAtomMetadata) {
    AStatsManager_PullAtomMetadata* metadata = NULL;
    EXPECT_DEATH(AStatsManager_PullAtomMetadata_obtain(), kLoadFailed);
    EXPECT_DEATH(AStatsManager_PullAtomMetadata_release(metadata), kLoadFailed);
    EXPECT_DEATH(AStatsManager_PullAtomMetadata_setCoolDownMillis(metadata, 0), kLoadFailed);
    EXPECT_DEATH(AStatsManager_PullAtomMetadata_getCoolDownMillis(metadata), kLoadFailed);
    EXPECT_DEATH(AStatsManager_PullAtomMetadata_setTimeoutMillis(metadata, 0), kLoadFailed);
    EXPECT_DEATH(AStatsManager_PullAtomMetadata_getTimeoutMillis(metadata), kLoadFailed);
    EXPECT_DEATH(AStatsManager_PullAtomMetadata_setAdditiveFields(metadata, NULL, 0), kLoadFailed);
    EXPECT_DEATH(AStatsManager_PullAtomMetadata_getNumAdditiveFields(metadata), kLoadFailed);
    EXPECT_DEATH(AStatsManager_PullAtomMetadata_getAdditiveFields(metadata, NULL), kLoadFailed);
}

TEST_F(LibstatspullLazyTest, NoLibstatspullForAStatsEventList) {
    AStatsEventList* event_list = NULL;
    EXPECT_DEATH(AStatsEventList_addStatsEvent(event_list), kLoadFailed);
}

TEST_F(LibstatspullLazyTest, NoLibstatspullForPullAtomCallback) {
    AStatsManager_PullAtomCallback callback = NULL;
    EXPECT_DEATH(AStatsManager_setPullAtomCallback(0, NULL, callback, NULL), kLoadFailed);
    EXPECT_DEATH(AStatsManager_clearPullAtomCallback(0), kLoadFailed);
}
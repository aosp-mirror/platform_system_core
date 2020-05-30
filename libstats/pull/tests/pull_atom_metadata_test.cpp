/*
 * Copyright (C) 2020, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>

#include <stats_pull_atom_callback.h>

namespace {

static const int64_t DEFAULT_COOL_DOWN_MILLIS = 1000LL;  // 1 second.
static const int64_t DEFAULT_TIMEOUT_MILLIS = 2000LL;    // 2 seconds.

}  // anonymous namespace

TEST(AStatsManager_PullAtomMetadataTest, TestEmpty) {
    AStatsManager_PullAtomMetadata* metadata = AStatsManager_PullAtomMetadata_obtain();
    EXPECT_EQ(AStatsManager_PullAtomMetadata_getCoolDownMillis(metadata), DEFAULT_COOL_DOWN_MILLIS);
    EXPECT_EQ(AStatsManager_PullAtomMetadata_getTimeoutMillis(metadata), DEFAULT_TIMEOUT_MILLIS);
    EXPECT_EQ(AStatsManager_PullAtomMetadata_getNumAdditiveFields(metadata), 0);
    AStatsManager_PullAtomMetadata_release(metadata);
}

TEST(AStatsManager_PullAtomMetadataTest, TestSetTimeoutMillis) {
    int64_t timeoutMillis = 500;
    AStatsManager_PullAtomMetadata* metadata = AStatsManager_PullAtomMetadata_obtain();
    AStatsManager_PullAtomMetadata_setTimeoutMillis(metadata, timeoutMillis);
    EXPECT_EQ(AStatsManager_PullAtomMetadata_getCoolDownMillis(metadata), DEFAULT_COOL_DOWN_MILLIS);
    EXPECT_EQ(AStatsManager_PullAtomMetadata_getTimeoutMillis(metadata), timeoutMillis);
    EXPECT_EQ(AStatsManager_PullAtomMetadata_getNumAdditiveFields(metadata), 0);
    AStatsManager_PullAtomMetadata_release(metadata);
}

TEST(AStatsManager_PullAtomMetadataTest, TestSetCoolDownMillis) {
    int64_t coolDownMillis = 10000;
    AStatsManager_PullAtomMetadata* metadata = AStatsManager_PullAtomMetadata_obtain();
    AStatsManager_PullAtomMetadata_setCoolDownMillis(metadata, coolDownMillis);
    EXPECT_EQ(AStatsManager_PullAtomMetadata_getCoolDownMillis(metadata), coolDownMillis);
    EXPECT_EQ(AStatsManager_PullAtomMetadata_getTimeoutMillis(metadata), DEFAULT_TIMEOUT_MILLIS);
    EXPECT_EQ(AStatsManager_PullAtomMetadata_getNumAdditiveFields(metadata), 0);
    AStatsManager_PullAtomMetadata_release(metadata);
}

TEST(AStatsManager_PullAtomMetadataTest, TestSetAdditiveFields) {
    const int numFields = 3;
    int inputFields[numFields] = {2, 4, 6};
    AStatsManager_PullAtomMetadata* metadata = AStatsManager_PullAtomMetadata_obtain();
    AStatsManager_PullAtomMetadata_setAdditiveFields(metadata, inputFields, numFields);
    EXPECT_EQ(AStatsManager_PullAtomMetadata_getCoolDownMillis(metadata), DEFAULT_COOL_DOWN_MILLIS);
    EXPECT_EQ(AStatsManager_PullAtomMetadata_getTimeoutMillis(metadata), DEFAULT_TIMEOUT_MILLIS);
    EXPECT_EQ(AStatsManager_PullAtomMetadata_getNumAdditiveFields(metadata), numFields);
    int outputFields[numFields];
    AStatsManager_PullAtomMetadata_getAdditiveFields(metadata, outputFields);
    for (int i = 0; i < numFields; i++) {
        EXPECT_EQ(inputFields[i], outputFields[i]);
    }
    AStatsManager_PullAtomMetadata_release(metadata);
}

TEST(AStatsManager_PullAtomMetadataTest, TestSetAllElements) {
    int64_t timeoutMillis = 500;
    int64_t coolDownMillis = 10000;
    const int numFields = 3;
    int inputFields[numFields] = {2, 4, 6};

    AStatsManager_PullAtomMetadata* metadata = AStatsManager_PullAtomMetadata_obtain();
    AStatsManager_PullAtomMetadata_setTimeoutMillis(metadata, timeoutMillis);
    AStatsManager_PullAtomMetadata_setCoolDownMillis(metadata, coolDownMillis);
    AStatsManager_PullAtomMetadata_setAdditiveFields(metadata, inputFields, numFields);

    EXPECT_EQ(AStatsManager_PullAtomMetadata_getCoolDownMillis(metadata), coolDownMillis);
    EXPECT_EQ(AStatsManager_PullAtomMetadata_getTimeoutMillis(metadata), timeoutMillis);
    EXPECT_EQ(AStatsManager_PullAtomMetadata_getNumAdditiveFields(metadata), numFields);
    int outputFields[numFields];
    AStatsManager_PullAtomMetadata_getAdditiveFields(metadata, outputFields);
    for (int i = 0; i < numFields; i++) {
        EXPECT_EQ(inputFields[i], outputFields[i]);
    }
    AStatsManager_PullAtomMetadata_release(metadata);
}

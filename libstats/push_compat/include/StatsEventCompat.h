/*
 * Copyright (C) 2019 The Android Open Source Project
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

#pragma once

#include <gtest/gtest_prod.h>
#include <map>
#include <mutex>
#include <vector>
#include "stats_event.h"
#include "stats_event_list.h"

using std::map;
using std::vector;

struct AStatsEventApi {
    // Indicates whether the below function pointers have been set using dlsym.
    bool initialized = false;

    AStatsEvent* (*obtain)(void);
    void (*build)(AStatsEvent*);
    int (*write)(AStatsEvent*);
    void (*release)(AStatsEvent*);
    void (*setAtomId)(AStatsEvent*, uint32_t);
    void (*writeInt32)(AStatsEvent*, int32_t);
    void (*writeInt64)(AStatsEvent*, int64_t);
    void (*writeFloat)(AStatsEvent*, float);
    void (*writeBool)(AStatsEvent*, bool);
    void (*writeByteArray)(AStatsEvent*, const uint8_t*, size_t);
    void (*writeString)(AStatsEvent*, const char*);
    void (*writeAttributionChain)(AStatsEvent*, const uint32_t*, const char* const*, uint8_t);
    void (*addBoolAnnotation)(AStatsEvent*, uint8_t, bool);
    void (*addInt32Annotation)(AStatsEvent*, uint8_t, int32_t);
};

class StatsEventCompat {
  public:
    StatsEventCompat();
    ~StatsEventCompat();

    void setAtomId(int32_t atomId);
    void writeInt32(int32_t value);
    void writeInt64(int64_t value);
    void writeFloat(float value);
    void writeBool(bool value);
    void writeByteArray(const char* buffer, size_t length);
    void writeString(const char* value);

    // Pre-condition: numUids == tags.size()
    void writeAttributionChain(const int32_t* uids, size_t numUids,
                               const vector<const char*>& tags);

    void writeKeyValuePairs(const map<int, int32_t>& int32Map, const map<int, int64_t>& int64Map,
                            const map<int, const char*>& stringMap,
                            const map<int, float>& floatMap);

    void addBoolAnnotation(uint8_t annotationId, bool value);
    void addInt32Annotation(uint8_t annotationId, int32_t value);

    int writeToSocket();

  private:
    // static member variables
    const static bool mPlatformAtLeastR;
    static bool mAttemptedLoad;
    static std::mutex mLoadLock;
    static AStatsEventApi mAStatsEventApi;

    // non-static member variables
    AStatsEvent* mEventR = nullptr;
    stats_event_list mEventQ;

    template <class T>
    void writeKeyValuePairMap(const map<int, T>& keyValuePairMap);

    void initializeApiTableLocked(void* handle);
    bool useRSchema();
    bool useQSchema();

    FRIEND_TEST(StatsEventCompatTest, TestDynamicLoading);
};

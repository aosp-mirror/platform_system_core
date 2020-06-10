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

#include "include/StatsEventCompat.h"

#include <chrono>

#include <android-base/chrono_utils.h>
#include <android-base/properties.h>
#include <android/api-level.h>
#include <android/log.h>
#include <dlfcn.h>

using android::base::boot_clock;
using android::base::GetProperty;

const static int kStatsEventTag = 1937006964;
const bool StatsEventCompat::mPlatformAtLeastR =
        android_get_device_api_level() >= __ANDROID_API_R__;

// initializations of static class variables
bool StatsEventCompat::mAttemptedLoad = false;
std::mutex StatsEventCompat::mLoadLock;
AStatsEventApi StatsEventCompat::mAStatsEventApi;

static int64_t elapsedRealtimeNano() {
    return std::chrono::time_point_cast<std::chrono::nanoseconds>(boot_clock::now())
            .time_since_epoch()
            .count();
}

StatsEventCompat::StatsEventCompat() : mEventQ(kStatsEventTag) {
    // guard loading because StatsEventCompat might be called from multithreaded
    // environment
    {
        std::lock_guard<std::mutex> lg(mLoadLock);
        if (!mAttemptedLoad && mPlatformAtLeastR) {
            void* handle = dlopen("libstatssocket.so", RTLD_NOW);
            if (handle) {
                initializeApiTableLocked(handle);
            } else {
                ALOGE("dlopen failed: %s\n", dlerror());
            }
        }
        mAttemptedLoad = true;
    }

    if (useRSchema()) {
        mEventR = mAStatsEventApi.obtain();
    } else if (useQSchema()) {
        mEventQ << elapsedRealtimeNano();
    }
}

StatsEventCompat::~StatsEventCompat() {
    if (useRSchema()) mAStatsEventApi.release(mEventR);
}

// Populates the AStatsEventApi struct by calling dlsym to find the address of
// each API function.
void StatsEventCompat::initializeApiTableLocked(void* handle) {
    mAStatsEventApi.obtain = (AStatsEvent* (*)())dlsym(handle, "AStatsEvent_obtain");
    mAStatsEventApi.build = (void (*)(AStatsEvent*))dlsym(handle, "AStatsEvent_build");
    mAStatsEventApi.write = (int (*)(AStatsEvent*))dlsym(handle, "AStatsEvent_write");
    mAStatsEventApi.release = (void (*)(AStatsEvent*))dlsym(handle, "AStatsEvent_release");
    mAStatsEventApi.setAtomId =
            (void (*)(AStatsEvent*, uint32_t))dlsym(handle, "AStatsEvent_setAtomId");
    mAStatsEventApi.writeInt32 =
            (void (*)(AStatsEvent*, int32_t))dlsym(handle, "AStatsEvent_writeInt32");
    mAStatsEventApi.writeInt64 =
            (void (*)(AStatsEvent*, int64_t))dlsym(handle, "AStatsEvent_writeInt64");
    mAStatsEventApi.writeFloat =
            (void (*)(AStatsEvent*, float))dlsym(handle, "AStatsEvent_writeFloat");
    mAStatsEventApi.writeBool =
            (void (*)(AStatsEvent*, bool))dlsym(handle, "AStatsEvent_writeBool");
    mAStatsEventApi.writeByteArray = (void (*)(AStatsEvent*, const uint8_t*, size_t))dlsym(
            handle, "AStatsEvent_writeByteArray");
    mAStatsEventApi.writeString =
            (void (*)(AStatsEvent*, const char*))dlsym(handle, "AStatsEvent_writeString");
    mAStatsEventApi.writeAttributionChain =
            (void (*)(AStatsEvent*, const uint32_t*, const char* const*, uint8_t))dlsym(
                    handle, "AStatsEvent_writeAttributionChain");
    mAStatsEventApi.addBoolAnnotation =
            (void (*)(AStatsEvent*, uint8_t, bool))dlsym(handle, "AStatsEvent_addBoolAnnotation");
    mAStatsEventApi.addInt32Annotation = (void (*)(AStatsEvent*, uint8_t, int32_t))dlsym(
            handle, "AStatsEvent_addInt32Annotation");

    mAStatsEventApi.initialized = true;
}

void StatsEventCompat::setAtomId(int32_t atomId) {
    if (useRSchema()) {
        mAStatsEventApi.setAtomId(mEventR, (uint32_t)atomId);
    } else if (useQSchema()) {
        mEventQ << atomId;
    }
}

void StatsEventCompat::writeInt32(int32_t value) {
    if (useRSchema()) {
        mAStatsEventApi.writeInt32(mEventR, value);
    } else if (useQSchema()) {
        mEventQ << value;
    }
}

void StatsEventCompat::writeInt64(int64_t value) {
    if (useRSchema()) {
        mAStatsEventApi.writeInt64(mEventR, value);
    } else if (useQSchema()) {
        mEventQ << value;
    }
}

void StatsEventCompat::writeFloat(float value) {
    if (useRSchema()) {
        mAStatsEventApi.writeFloat(mEventR, value);
    } else if (useQSchema()) {
        mEventQ << value;
    }
}

void StatsEventCompat::writeBool(bool value) {
    if (useRSchema()) {
        mAStatsEventApi.writeBool(mEventR, value);
    } else if (useQSchema()) {
        mEventQ << value;
    }
}

void StatsEventCompat::writeByteArray(const char* buffer, size_t length) {
    if (useRSchema()) {
        mAStatsEventApi.writeByteArray(mEventR, reinterpret_cast<const uint8_t*>(buffer), length);
    } else if (useQSchema()) {
        mEventQ.AppendCharArray(buffer, length);
    }
}

void StatsEventCompat::writeString(const char* value) {
    if (value == nullptr) value = "";

    if (useRSchema()) {
        mAStatsEventApi.writeString(mEventR, value);
    } else if (useQSchema()) {
        mEventQ << value;
    }
}

void StatsEventCompat::writeAttributionChain(const int32_t* uids, size_t numUids,
                                             const vector<const char*>& tags) {
    if (useRSchema()) {
        mAStatsEventApi.writeAttributionChain(mEventR, (const uint32_t*)uids, tags.data(),
                                              (uint8_t)numUids);
    } else if (useQSchema()) {
        mEventQ.begin();
        for (size_t i = 0; i < numUids; i++) {
            mEventQ.begin();
            mEventQ << uids[i];
            const char* tag = tags[i] ? tags[i] : "";
            mEventQ << tag;
            mEventQ.end();
        }
        mEventQ.end();
    }
}

void StatsEventCompat::writeKeyValuePairs(const map<int, int32_t>& int32Map,
                                          const map<int, int64_t>& int64Map,
                                          const map<int, const char*>& stringMap,
                                          const map<int, float>& floatMap) {
    // AStatsEvent does not support key value pairs.
    if (useQSchema()) {
        mEventQ.begin();
        writeKeyValuePairMap(int32Map);
        writeKeyValuePairMap(int64Map);
        writeKeyValuePairMap(stringMap);
        writeKeyValuePairMap(floatMap);
        mEventQ.end();
    }
}

template <class T>
void StatsEventCompat::writeKeyValuePairMap(const map<int, T>& keyValuePairMap) {
    for (const auto& it : keyValuePairMap) {
        mEventQ.begin();
        mEventQ << it.first;
        mEventQ << it.second;
        mEventQ.end();
    }
}

// explicitly specify which types we're going to use
template void StatsEventCompat::writeKeyValuePairMap<int32_t>(const map<int, int32_t>&);
template void StatsEventCompat::writeKeyValuePairMap<int64_t>(const map<int, int64_t>&);
template void StatsEventCompat::writeKeyValuePairMap<float>(const map<int, float>&);
template void StatsEventCompat::writeKeyValuePairMap<const char*>(const map<int, const char*>&);

void StatsEventCompat::addBoolAnnotation(uint8_t annotationId, bool value) {
    if (useRSchema()) {
        mAStatsEventApi.addBoolAnnotation(mEventR, annotationId, value);
    }
    // Don't do anything if on Q.
}

void StatsEventCompat::addInt32Annotation(uint8_t annotationId, int32_t value) {
    if (useRSchema()) {
        mAStatsEventApi.addInt32Annotation(mEventR, annotationId, value);
    }
    // Don't do anything if on Q.
}

int StatsEventCompat::writeToSocket() {
    if (useRSchema()) {
        return mAStatsEventApi.write(mEventR);
    }

    if (useQSchema()) return mEventQ.write(LOG_ID_STATS);

    // We reach here only if we're on R, but libstatssocket was unable to
    // be loaded using dlopen.
    return -ENOLINK;
}

bool StatsEventCompat::useRSchema() {
    return mPlatformAtLeastR && mAStatsEventApi.initialized;
}

bool StatsEventCompat::useQSchema() {
    return !mPlatformAtLeastR;
}

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

/* Checking ro.build.version.release is fragile, as the release field is
 * an opaque string without structural guarantees. However, testing confirms
 * that on Q devices, the property is "10," and on R, it is "R." Until
 * android_get_device_api_level() is updated, this is the only solution.
 *
 * TODO(b/146019024): migrate to android_get_device_api_level()
 */
const bool StatsEventCompat::mPlatformAtLeastR =
        GetProperty("ro.build.version.codename", "") == "R" ||
        android_get_device_api_level() > __ANDROID_API_Q__;

// definitions of static class variables
bool StatsEventCompat::mAttemptedLoad = false;
void* StatsEventCompat::mStatsEventApi = nullptr;
std::mutex StatsEventCompat::mLoadLock;

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
        if (!mAttemptedLoad) {
            void* handle = dlopen("libstatssocket.so", RTLD_NOW);
            if (handle) {
                //                mStatsEventApi = (struct AStatsEvent_apiTable*)dlsym(handle,
                //                "table");
            } else {
                ALOGE("dlopen failed: %s\n", dlerror());
            }
        }
        mAttemptedLoad = true;
    }

    if (mStatsEventApi) {
        //        mEventR = mStatsEventApi->obtain();
    } else if (!mPlatformAtLeastR) {
        mEventQ << elapsedRealtimeNano();
    }
}

StatsEventCompat::~StatsEventCompat() {
    //    if (mStatsEventApi) mStatsEventApi->release(mEventR);
}

void StatsEventCompat::setAtomId(int32_t atomId) {
    if (mStatsEventApi) {
        //        mStatsEventApi->setAtomId(mEventR, (uint32_t)atomId);
    } else if (!mPlatformAtLeastR) {
        mEventQ << atomId;
    }
}

void StatsEventCompat::writeInt32(int32_t value) {
    if (mStatsEventApi) {
        //        mStatsEventApi->writeInt32(mEventR, value);
    } else if (!mPlatformAtLeastR) {
        mEventQ << value;
    }
}

void StatsEventCompat::writeInt64(int64_t value) {
    if (mStatsEventApi) {
        //        mStatsEventApi->writeInt64(mEventR, value);
    } else if (!mPlatformAtLeastR) {
        mEventQ << value;
    }
}

void StatsEventCompat::writeFloat(float value) {
    if (mStatsEventApi) {
        //        mStatsEventApi->writeFloat(mEventR, value);
    } else if (!mPlatformAtLeastR) {
        mEventQ << value;
    }
}

void StatsEventCompat::writeBool(bool value) {
    if (mStatsEventApi) {
        //        mStatsEventApi->writeBool(mEventR, value);
    } else if (!mPlatformAtLeastR) {
        mEventQ << value;
    }
}

void StatsEventCompat::writeByteArray(const char* buffer, size_t length) {
    if (mStatsEventApi) {
        //        mStatsEventApi->writeByteArray(mEventR, (const uint8_t*)buffer, length);
    } else if (!mPlatformAtLeastR) {
        mEventQ.AppendCharArray(buffer, length);
    }
}

void StatsEventCompat::writeString(const char* value) {
    if (value == nullptr) value = "";

    if (mStatsEventApi) {
        //        mStatsEventApi->writeString(mEventR, value);
    } else if (!mPlatformAtLeastR) {
        mEventQ << value;
    }
}

void StatsEventCompat::writeAttributionChain(const int32_t* uids, size_t numUids,
                                             const vector<const char*>& tags) {
    if (mStatsEventApi) {
        //        mStatsEventApi->writeAttributionChain(mEventR, (const uint32_t*)uids, tags.data(),
        //                                                (uint8_t)numUids);
    } else if (!mPlatformAtLeastR) {
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
    // Key value pairs are not supported with AStatsEvent.
    if (!mPlatformAtLeastR) {
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
    // Workaround for unused params.
    (void)annotationId;
    (void)value;
    //    if (mStatsEventApi) mStatsEventApi->addBoolAnnotation(mEventR, annotationId, value);
    // Don't do anything if on Q.
}

void StatsEventCompat::addInt32Annotation(uint8_t annotationId, int32_t value) {
    // Workaround for unused params.
    (void)annotationId;
    (void)value;
    //    if (mStatsEventApi) mStatsEventApi->addInt32Annotation(mEventR, annotationId, value);
    // Don't do anything if on Q.
}

int StatsEventCompat::writeToSocket() {
    if (mStatsEventApi) {
        //        mStatsEventApi->build(mEventR);
        //        return mStatsEventApi->write(mEventR);
    }

    if (!mPlatformAtLeastR) return mEventQ.write(LOG_ID_STATS);

    // We reach here only if we're on R, but libstatspush_compat was unable to
    // be loaded using dlopen.
    return -ENOLINK;
}

bool StatsEventCompat::usesNewSchema() {
    return mStatsEventApi != nullptr;
}

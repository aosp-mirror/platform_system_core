/*
 * Copyright (C) 2019, The Android Open Source Project
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

#include <map>
#include <vector>

#include <stats_event.h>
#include <stats_pull_atom_callback.h>

#include <android/os/BnPullAtomCallback.h>
#include <android/os/IPullAtomResultReceiver.h>
#include <android/os/IStatsd.h>
#include <android/util/StatsEventParcel.h>
#include <binder/IServiceManager.h>
#include "include/stats_pull_atom_callback.h"

struct pulled_stats_event_list {
    std::vector<stats_event*> data;
};

struct stats_event* add_stats_event_to_pull_data(pulled_stats_event_list* pull_data) {
    struct stats_event* event = stats_event_obtain();
    pull_data->data.push_back(event);
    return event;
}

static const int64_t DEFAULT_COOL_DOWN_NS = 1000000000LL;  // 1 second.
static const int64_t DEFAULT_TIMEOUT_NS = 10000000000LL;   // 10 seconds.

class StatsPullAtomCallbackInternal : public android::os::BnPullAtomCallback {
  public:
    StatsPullAtomCallbackInternal(const stats_pull_atom_callback_t callback, const void* cookie,
                                  const int64_t coolDownNs, const int64_t timeoutNs,
                                  const std::vector<int32_t> additiveFields)
        : mCallback(callback),
          mCookie(cookie),
          mCoolDownNs(coolDownNs),
          mTimeoutNs(timeoutNs),
          mAdditiveFields(additiveFields) {}

    ::android::binder::Status onPullAtom(
            int32_t atomTag,
            const ::android::sp<::android::os::IPullAtomResultReceiver>& resultReceiver) override {
        pulled_stats_event_list statsEventList;
        bool success = mCallback(atomTag, &statsEventList, mCookie);

        // Convert stats_events into StatsEventParcels.
        std::vector<android::util::StatsEventParcel> parcels;
        for (int i = 0; i < statsEventList.data.size(); i++) {
            size_t size;
            uint8_t* buffer = stats_event_get_buffer(statsEventList.data[i], &size);

            android::util::StatsEventParcel p;
            // vector.assign() creates a copy, but this is inevitable unless
            // stats_event.h/c uses a vector as opposed to a buffer.
            p.buffer.assign(buffer, buffer + size);
            parcels.push_back(std::move(p));
        }

        resultReceiver->pullFinished(atomTag, success, parcels);
        for (int i = 0; i < statsEventList.data.size(); i++) {
            stats_event_release(statsEventList.data[i]);
        }
        return android::binder::Status::ok();
    }

    const int64_t& getCoolDownNs() const { return mCoolDownNs; }
    const int64_t& getTimeoutNs() const { return mTimeoutNs; }
    const std::vector<int32_t>& getAdditiveFields() const { return mAdditiveFields; }

  private:
    const stats_pull_atom_callback_t mCallback;
    const void* mCookie;
    const int64_t mCoolDownNs;
    const int64_t mTimeoutNs;
    const std::vector<int32_t> mAdditiveFields;
};

static std::mutex pullAtomMutex;
static android::sp<android::os::IStatsd> sStatsd = nullptr;

static std::map<int32_t, android::sp<StatsPullAtomCallbackInternal>> mPullers;
static android::sp<android::os::IStatsd> getStatsServiceLocked();

class StatsDeathRecipient : public android::IBinder::DeathRecipient {
  public:
    StatsDeathRecipient() = default;
    ~StatsDeathRecipient() override = default;

    // android::IBinder::DeathRecipient override:
    void binderDied(const android::wp<android::IBinder>& /* who */) override {
        std::lock_guard<std::mutex> lock(pullAtomMutex);
        if (sStatsd) {
            sStatsd = nullptr;
        }
        android::sp<android::os::IStatsd> statsService = getStatsServiceLocked();
        if (statsService == nullptr) {
            return;
        }
        for (auto it : mPullers) {
            statsService->registerNativePullAtomCallback(it.first, it.second->getCoolDownNs(),
                                                         it.second->getTimeoutNs(),
                                                         it.second->getAdditiveFields(), it.second);
        }
    }
};

static android::sp<StatsDeathRecipient> statsDeathRecipient = new StatsDeathRecipient();

static android::sp<android::os::IStatsd> getStatsServiceLocked() {
    if (!sStatsd) {
        // Fetch statsd.
        const android::sp<android::IBinder> binder =
                android::defaultServiceManager()->checkService(android::String16("stats"));
        if (!binder) {
            return nullptr;
        }
        binder->linkToDeath(statsDeathRecipient);
        sStatsd = android::interface_cast<android::os::IStatsd>(binder);
    }
    return sStatsd;
}

void register_stats_pull_atom_callback(int32_t atom_tag, stats_pull_atom_callback_t callback,
                                       pull_atom_metadata* metadata, void* cookie) {
    int64_t coolDownNs = metadata == nullptr ? DEFAULT_COOL_DOWN_NS : metadata->cool_down_ns;
    int64_t timeoutNs = metadata == nullptr ? DEFAULT_TIMEOUT_NS : metadata->timeout_ns;

    std::vector<int32_t> additiveFields;
    if (metadata != nullptr && metadata->additive_fields != nullptr) {
        additiveFields.assign(metadata->additive_fields,
                              metadata->additive_fields + metadata->additive_fields_size);
    }

    std::lock_guard<std::mutex> lg(pullAtomMutex);
    const android::sp<android::os::IStatsd> statsService = getStatsServiceLocked();
    if (statsService == nullptr) {
        // Error - statsd not available
        return;
    }

    android::sp<StatsPullAtomCallbackInternal> callbackBinder = new StatsPullAtomCallbackInternal(
            callback, cookie, coolDownNs, timeoutNs, additiveFields);
    mPullers[atom_tag] = callbackBinder;
    statsService->registerNativePullAtomCallback(atom_tag, coolDownNs, timeoutNs, additiveFields,
                                                 callbackBinder);
}

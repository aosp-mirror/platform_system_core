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
#include <thread>
#include <vector>

#include <stats_event.h>
#include <stats_pull_atom_callback.h>

#include <aidl/android/os/BnPullAtomCallback.h>
#include <aidl/android/os/IPullAtomResultReceiver.h>
#include <aidl/android/os/IStatsd.h>
#include <aidl/android/util/StatsEventParcel.h>
#include <android/binder_auto_utils.h>
#include <android/binder_ibinder.h>
#include <android/binder_manager.h>

using Status = ::ndk::ScopedAStatus;
using aidl::android::os::BnPullAtomCallback;
using aidl::android::os::IPullAtomResultReceiver;
using aidl::android::os::IStatsd;
using aidl::android::util::StatsEventParcel;
using ::ndk::SharedRefBase;

struct AStatsEventList {
    std::vector<AStatsEvent*> data;
};

AStatsEvent* AStatsEventList_addStatsEvent(AStatsEventList* pull_data) {
    AStatsEvent* event = AStatsEvent_obtain();
    pull_data->data.push_back(event);
    return event;
}

static const int64_t DEFAULT_COOL_DOWN_MILLIS = 1000LL;  // 1 second.
static const int64_t DEFAULT_TIMEOUT_MILLIS = 2000LL;    // 2 seconds.

struct AStatsManager_PullAtomMetadata {
    int64_t cool_down_millis;
    int64_t timeout_millis;
    std::vector<int32_t> additive_fields;
};

AStatsManager_PullAtomMetadata* AStatsManager_PullAtomMetadata_obtain() {
    AStatsManager_PullAtomMetadata* metadata = new AStatsManager_PullAtomMetadata();
    metadata->cool_down_millis = DEFAULT_COOL_DOWN_MILLIS;
    metadata->timeout_millis = DEFAULT_TIMEOUT_MILLIS;
    metadata->additive_fields = std::vector<int32_t>();
    return metadata;
}

void AStatsManager_PullAtomMetadata_release(AStatsManager_PullAtomMetadata* metadata) {
    delete metadata;
}

void AStatsManager_PullAtomMetadata_setCoolDownMillis(AStatsManager_PullAtomMetadata* metadata,
                                                      int64_t cool_down_millis) {
    metadata->cool_down_millis = cool_down_millis;
}

int64_t AStatsManager_PullAtomMetadata_getCoolDownMillis(AStatsManager_PullAtomMetadata* metadata) {
    return metadata->cool_down_millis;
}

void AStatsManager_PullAtomMetadata_setTimeoutMillis(AStatsManager_PullAtomMetadata* metadata,
                                                     int64_t timeout_millis) {
    metadata->timeout_millis = timeout_millis;
}

int64_t AStatsManager_PullAtomMetadata_getTimeoutMillis(AStatsManager_PullAtomMetadata* metadata) {
    return metadata->timeout_millis;
}

void AStatsManager_PullAtomMetadata_setAdditiveFields(AStatsManager_PullAtomMetadata* metadata,
                                                      int32_t* additive_fields,
                                                      int32_t num_fields) {
    metadata->additive_fields.assign(additive_fields, additive_fields + num_fields);
}

int32_t AStatsManager_PullAtomMetadata_getNumAdditiveFields(
        AStatsManager_PullAtomMetadata* metadata) {
    return metadata->additive_fields.size();
}

void AStatsManager_PullAtomMetadata_getAdditiveFields(AStatsManager_PullAtomMetadata* metadata,
                                                      int32_t* fields) {
    std::copy(metadata->additive_fields.begin(), metadata->additive_fields.end(), fields);
}

class StatsPullAtomCallbackInternal : public BnPullAtomCallback {
  public:
    StatsPullAtomCallbackInternal(const AStatsManager_PullAtomCallback callback, void* cookie,
                                  const int64_t coolDownMillis, const int64_t timeoutMillis,
                                  const std::vector<int32_t> additiveFields)
        : mCallback(callback),
          mCookie(cookie),
          mCoolDownMillis(coolDownMillis),
          mTimeoutMillis(timeoutMillis),
          mAdditiveFields(additiveFields) {}

    Status onPullAtom(int32_t atomTag,
                      const std::shared_ptr<IPullAtomResultReceiver>& resultReceiver) override {
        AStatsEventList statsEventList;
        int successInt = mCallback(atomTag, &statsEventList, mCookie);
        bool success = successInt == AStatsManager_PULL_SUCCESS;

        // Convert stats_events into StatsEventParcels.
        std::vector<StatsEventParcel> parcels;
        for (int i = 0; i < statsEventList.data.size(); i++) {
            size_t size;
            uint8_t* buffer = AStatsEvent_getBuffer(statsEventList.data[i], &size);

            StatsEventParcel p;
            // vector.assign() creates a copy, but this is inevitable unless
            // stats_event.h/c uses a vector as opposed to a buffer.
            p.buffer.assign(buffer, buffer + size);
            parcels.push_back(std::move(p));
        }

        Status status = resultReceiver->pullFinished(atomTag, success, parcels);
        if (!status.isOk()) {
            std::vector<StatsEventParcel> emptyParcels;
            resultReceiver->pullFinished(atomTag, /*success=*/false, emptyParcels);
        }
        for (int i = 0; i < statsEventList.data.size(); i++) {
            AStatsEvent_release(statsEventList.data[i]);
        }
        return Status::ok();
    }

    int64_t getCoolDownMillis() const { return mCoolDownMillis; }
    int64_t getTimeoutMillis() const { return mTimeoutMillis; }
    const std::vector<int32_t>& getAdditiveFields() const { return mAdditiveFields; }

  private:
    const AStatsManager_PullAtomCallback mCallback;
    void* mCookie;
    const int64_t mCoolDownMillis;
    const int64_t mTimeoutMillis;
    const std::vector<int32_t> mAdditiveFields;
};

static std::mutex pullAtomMutex;
static std::shared_ptr<IStatsd> sStatsd = nullptr;

static std::map<int32_t, std::shared_ptr<StatsPullAtomCallbackInternal>> mPullers;
static std::shared_ptr<IStatsd> getStatsService();

static void binderDied(void* /*cookie*/) {
    {
        std::lock_guard<std::mutex> lock(pullAtomMutex);
        sStatsd = nullptr;
    }

    std::shared_ptr<IStatsd> statsService = getStatsService();
    if (statsService == nullptr) {
        return;
    }

    // Since we do not want to make an IPC with the lock held, we first create a
    // copy of the data with the lock held before iterating through the map.
    std::map<int32_t, std::shared_ptr<StatsPullAtomCallbackInternal>> pullersCopy;
    {
        std::lock_guard<std::mutex> lock(pullAtomMutex);
        pullersCopy = mPullers;
    }
    for (const auto& it : pullersCopy) {
        statsService->registerNativePullAtomCallback(it.first, it.second->getCoolDownMillis(),
                                                     it.second->getTimeoutMillis(),
                                                     it.second->getAdditiveFields(), it.second);
    }
}

static ::ndk::ScopedAIBinder_DeathRecipient sDeathRecipient(
        AIBinder_DeathRecipient_new(binderDied));

static std::shared_ptr<IStatsd> getStatsService() {
    std::lock_guard<std::mutex> lock(pullAtomMutex);
    if (!sStatsd) {
        // Fetch statsd
        ::ndk::SpAIBinder binder(AServiceManager_getService("stats"));
        sStatsd = IStatsd::fromBinder(binder);
        if (sStatsd) {
            AIBinder_linkToDeath(binder.get(), sDeathRecipient.get(), /*cookie=*/nullptr);
        }
    }
    return sStatsd;
}

void registerStatsPullAtomCallbackBlocking(int32_t atomTag,
                                           std::shared_ptr<StatsPullAtomCallbackInternal> cb) {
    const std::shared_ptr<IStatsd> statsService = getStatsService();
    if (statsService == nullptr) {
        // Statsd not available
        return;
    }

    statsService->registerNativePullAtomCallback(
            atomTag, cb->getCoolDownMillis(), cb->getTimeoutMillis(), cb->getAdditiveFields(), cb);
}

void unregisterStatsPullAtomCallbackBlocking(int32_t atomTag) {
    const std::shared_ptr<IStatsd> statsService = getStatsService();
    if (statsService == nullptr) {
        // Statsd not available
        return;
    }

    statsService->unregisterNativePullAtomCallback(atomTag);
}

void AStatsManager_setPullAtomCallback(int32_t atom_tag, AStatsManager_PullAtomMetadata* metadata,
                                       AStatsManager_PullAtomCallback callback, void* cookie) {
    int64_t coolDownMillis =
            metadata == nullptr ? DEFAULT_COOL_DOWN_MILLIS : metadata->cool_down_millis;
    int64_t timeoutMillis = metadata == nullptr ? DEFAULT_TIMEOUT_MILLIS : metadata->timeout_millis;

    std::vector<int32_t> additiveFields;
    if (metadata != nullptr) {
        additiveFields = metadata->additive_fields;
    }

    std::shared_ptr<StatsPullAtomCallbackInternal> callbackBinder =
            SharedRefBase::make<StatsPullAtomCallbackInternal>(callback, cookie, coolDownMillis,
                                                               timeoutMillis, additiveFields);

    {
        std::lock_guard<std::mutex> lg(pullAtomMutex);
        // Always add to the map. If statsd is dead, we will add them when it comes back.
        mPullers[atom_tag] = callbackBinder;
    }

    std::thread registerThread(registerStatsPullAtomCallbackBlocking, atom_tag, callbackBinder);
    registerThread.detach();
}

void AStatsManager_clearPullAtomCallback(int32_t atom_tag) {
    {
        std::lock_guard<std::mutex> lg(pullAtomMutex);
        // Always remove the puller from our map.
        // If statsd is down, we will not register it when it comes back.
        mPullers.erase(atom_tag);
    }
    std::thread unregisterThread(unregisterStatsPullAtomCallbackBlocking, atom_tag);
    unregisterThread.detach();
}

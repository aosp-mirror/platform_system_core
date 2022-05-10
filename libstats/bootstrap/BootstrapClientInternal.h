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

#pragma once

#include <android/os/IStatsBootstrapAtomService.h>

namespace android {
namespace os {
namespace stats {

class BootstrapClientInternal : public IBinder::DeathRecipient {
  public:
    static sp<BootstrapClientInternal> getInstance();
    void binderDied(const wp<IBinder>& who) override;
    sp<IStatsBootstrapAtomService> getServiceNonBlocking();

  private:
    BootstrapClientInternal() {}
    void connectNonBlockingLocked();

    mutable std::mutex mLock;
    sp<IStatsBootstrapAtomService> mService;
};

}  // namespace stats
}  // namespace os
}  // namespace android

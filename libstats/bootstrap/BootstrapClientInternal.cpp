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

#include "BootstrapClientInternal.h"

#include <binder/IServiceManager.h>

namespace android {
namespace os {
namespace stats {

sp<BootstrapClientInternal> BootstrapClientInternal::getInstance() {
    static sp<BootstrapClientInternal> client = new BootstrapClientInternal();
    return client;
}

sp<IStatsBootstrapAtomService> BootstrapClientInternal::getServiceNonBlocking() {
    std::lock_guard<std::mutex> lock(mLock);
    if (mService != nullptr) {
        return mService;
    }
    connectNonBlockingLocked();
    return mService;
}

void BootstrapClientInternal::binderDied(const wp<IBinder>&) {
    std::lock_guard<std::mutex> lock(mLock);
    mService = nullptr;
    connectNonBlockingLocked();
}

void BootstrapClientInternal::connectNonBlockingLocked() {
    const String16 name("statsbootstrap");
    mService =
            interface_cast<IStatsBootstrapAtomService>(defaultServiceManager()->checkService(name));
    if (mService != nullptr) {
        // Set up binder death.
        IInterface::asBinder(mService)->linkToDeath(this);
    }
}

}  // namespace stats
}  // namespace os
}  // namespace android
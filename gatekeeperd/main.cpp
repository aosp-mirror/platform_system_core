/*
 * Copyright (C) 2023 The Android Open Source Project
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

#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>

#include <log/log.h>

#include "gatekeeperd.h"

int main(int argc, char* argv[]) {
    ALOGI("Starting gatekeeperd...");
    if (argc < 2) {
        ALOGE("A directory must be specified!");
        return 1;
    }
    if (chdir(argv[1]) == -1) {
        ALOGE("chdir: %s: %s", argv[1], strerror(errno));
        return 1;
    }

    android::sp<android::IServiceManager> sm = android::defaultServiceManager();
    android::sp<android::GateKeeperProxy> proxy = new android::GateKeeperProxy();
    android::status_t ret = sm->addService(
            android::String16("android.service.gatekeeper.IGateKeeperService"), proxy);
    if (ret != android::OK) {
        ALOGE("Couldn't register binder service!");
        return 1;
    }

    /*
     * We're the only thread in existence, so we're just going to process
     * Binder transaction as a single-threaded program.
     */
    android::IPCThreadState::self()->joinThreadPool();
    return 1;
}

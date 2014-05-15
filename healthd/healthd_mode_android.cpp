/*
 * Copyright (C) 2013 The Android Open Source Project
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

#define LOG_TAG "healthd-android"

#include "healthd.h"
#include "BatteryPropertiesRegistrar.h"

#include <binder/IPCThreadState.h>
#include <binder/ProcessState.h>
#include <cutils/klog.h>
#include <sys/epoll.h>

using namespace android;

static int gBinderFd;
static sp<BatteryPropertiesRegistrar> gBatteryPropertiesRegistrar;

void healthd_mode_android_battery_update(
    struct android::BatteryProperties *props) {
    if (gBatteryPropertiesRegistrar != NULL)
        gBatteryPropertiesRegistrar->notifyListeners(*props);

    return;
}

int healthd_mode_android_preparetowait(void) {
    IPCThreadState::self()->flushCommands();
    return -1;
}

static void binder_event(uint32_t /*epevents*/) {
    IPCThreadState::self()->handlePolledCommands();
}

void healthd_mode_android_init(struct healthd_config* /*config*/) {
    ProcessState::self()->setThreadPoolMaxThreadCount(0);
    IPCThreadState::self()->disableBackgroundScheduling(true);
    IPCThreadState::self()->setupPolling(&gBinderFd);

    if (gBinderFd >= 0) {
        if (healthd_register_event(gBinderFd, binder_event))
            KLOG_ERROR(LOG_TAG,
                       "Register for binder events failed\n");
    }

    gBatteryPropertiesRegistrar = new BatteryPropertiesRegistrar();
    gBatteryPropertiesRegistrar->publish();
}

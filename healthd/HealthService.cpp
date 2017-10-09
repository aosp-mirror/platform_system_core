/*
 * Copyright 2017 The Android Open Source Project
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

// This is a reference implementation for health@2.0 HAL. A vendor
// can write its own HealthService.cpp with customized init and update functions.

#define LOG_TAG "health@2.0/" HEALTH_INSTANCE_NAME
#include <android-base/logging.h>

#include <android/hardware/health/1.0/types.h>
#include <hal_conversion.h>
#include <health2/Health.h>
#include <healthd/healthd.h>
#include <hidl/HidlTransportSupport.h>

using android::hardware::IPCThreadState;
using android::hardware::configureRpcThreadpool;
using android::hardware::health::V1_0::HealthInfo;
using android::hardware::health::V1_0::hal_conversion::convertToHealthInfo;
using android::hardware::health::V2_0::IHealth;
using android::hardware::health::V2_0::implementation::Health;

// see healthd_common.cpp
android::sp<IHealth> gHealth;

static int gBinderFd;

extern int healthd_main(void);

static void binder_event(uint32_t /*epevents*/) {
    IPCThreadState::self()->handlePolledCommands();
}

// TODO(b/67463967): healthd_board_* functions should be removed in health@2.0
int healthd_board_battery_update(struct android::BatteryProperties*)
{
    // return 0 to log periodic polled battery status to kernel log
    return 0;
}

void healthd_mode_service_2_0_init(struct healthd_config* config) {
    LOG(INFO) << LOG_TAG << " Hal is starting up...";

    // Implementation-defined init logic goes here.
    // 1. config->periodic_chores_interval_* variables
    // 2. config->battery*Path variables
    // 3. config->energyCounter. In this implementation, energyCounter is not defined.

    configureRpcThreadpool(1, false /* callerWillJoin */);
    IPCThreadState::self()->disableBackgroundScheduling(true);
    IPCThreadState::self()->setupPolling(&gBinderFd);

    if (gBinderFd >= 0) {
        if (healthd_register_event(gBinderFd, binder_event))
            LOG(ERROR) << LOG_TAG << ": Register for binder events failed";
    }

    gHealth = new ::android::hardware::health::V2_0::implementation::Health(config);
    CHECK_EQ(gHealth->registerAsService(HEALTH_INSTANCE_NAME), android::OK)
        << LOG_TAG << ": Failed to register HAL";

    LOG(INFO) << LOG_TAG << ": Hal init done";
}

int healthd_mode_service_2_0_preparetowait(void) {
    IPCThreadState::self()->flushCommands();
    return -1;
}

void healthd_mode_service_2_0_heartbeat(void) {
    // noop
}

void healthd_mode_service_2_0_battery_update(struct android::BatteryProperties* prop) {

    // Implementation-defined update logic goes here. An implementation
    // can make modifications to prop before broadcasting it to all callbacks.

    HealthInfo info;
    convertToHealthInfo(prop, info);
    static_cast<Health*>(gHealth.get())->notifyListeners(info);
}

static struct healthd_mode_ops healthd_mode_service_2_0_ops = {
    .init = healthd_mode_service_2_0_init,
    .preparetowait = healthd_mode_service_2_0_preparetowait,
    .heartbeat = healthd_mode_service_2_0_heartbeat,
    .battery_update = healthd_mode_service_2_0_battery_update,
};

int main() {
    healthd_mode_ops = &healthd_mode_service_2_0_ops;
    LOG(INFO) << LOG_TAG << ": Hal starting main loop...";
    return healthd_main();
}

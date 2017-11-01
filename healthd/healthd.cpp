/*
 * Copyright (C) 2016 The Android Open Source Project
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

#define LOG_TAG "healthd"
#define KLOG_LEVEL 6

#include <healthd/healthd.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <cutils/klog.h>

#include <android/hardware/health/1.0/IHealth.h>
#include <android/hardware/health/1.0/types.h>
#include <hal_conversion.h>

using namespace android;

using IHealth = ::android::hardware::health::V1_0::IHealth;
using Result = ::android::hardware::health::V1_0::Result;
using HealthConfig = ::android::hardware::health::V1_0::HealthConfig;
using HealthInfo = ::android::hardware::health::V1_0::HealthInfo;

using ::android::hardware::health::V1_0::hal_conversion::convertToHealthConfig;
using ::android::hardware::health::V1_0::hal_conversion::convertFromHealthConfig;
using ::android::hardware::health::V1_0::hal_conversion::convertToHealthInfo;
using ::android::hardware::health::V1_0::hal_conversion::convertFromHealthInfo;

// device specific hal interface;
static sp<IHealth> gHealth;

// main healthd loop
extern int healthd_main(void);

// Android mode
extern void healthd_mode_android_init(struct healthd_config *config);
extern int healthd_mode_android_preparetowait(void);
extern void healthd_mode_android_heartbeat(void);
extern void healthd_mode_android_battery_update(
    struct android::BatteryProperties *props);

static struct healthd_mode_ops android_ops = {
    .init = healthd_mode_android_init,
    .preparetowait = healthd_mode_android_preparetowait,
    .heartbeat = healthd_mode_android_heartbeat,
    .battery_update = healthd_mode_android_battery_update,
};

// default energy counter property redirect to talk to device
// HAL
static int healthd_board_get_energy_counter(int64_t *energy) {

    if (gHealth == nullptr) {
        return NAME_NOT_FOUND;
    }

    Result result = Result::NOT_SUPPORTED;
    gHealth->energyCounter([=, &result] (Result ret, int64_t energyOut) {
                result = ret;
                *energy = energyOut;
            });

    return result == Result::SUCCESS ? OK : NAME_NOT_FOUND;
}

void healthd_board_init(struct healthd_config *config) {

    // Initialize the board HAL - Equivalent of healthd_board_init(config)
    // in charger/recovery mode.

    gHealth = IHealth::getService();
    if (gHealth == nullptr) {
        KLOG_WARNING(LOG_TAG, "unable to get HAL interface, using defaults\n");
        return;
    }

    HealthConfig halConfig;
    convertToHealthConfig(config, halConfig);
    gHealth->init(halConfig, [=] (const auto &halConfigOut) {
            convertFromHealthConfig(halConfigOut, config);
            // always redirect energy counter queries
            config->energyCounter = healthd_board_get_energy_counter;
            });
}

int healthd_board_battery_update(struct android::BatteryProperties *props) {
    int logthis = 0;

    if (gHealth == nullptr) {
        return logthis;
    }

    HealthInfo info;
    convertToHealthInfo(props, info);
    gHealth->update(info,
            [=, &logthis] (int32_t ret, const auto &infoOut) {
                logthis = ret;
                convertFromHealthInfo(infoOut, props);
            });

    return logthis;
}

int main(int /*argc*/, char ** /*argv*/) {

    healthd_mode_ops = &android_ops;

    return healthd_main();
}

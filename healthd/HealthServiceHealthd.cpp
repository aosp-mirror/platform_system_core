/*
 * Copyright (C) 2017 The Android Open Source Project
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
#include <android-base/logging.h>

#include <android/hardware/health/1.0/IHealth.h>
#include <android/hardware/health/1.0/types.h>
#include <hal_conversion.h>
#include <health2/service.h>
#include <healthd/healthd.h>
#include <hidl/HidlTransportSupport.h>

using android::OK;
using android::NAME_NOT_FOUND;
using android::hardware::health::V1_0::HealthConfig;
using android::hardware::health::V1_0::HealthInfo;
using android::hardware::health::V1_0::Result;
using android::hardware::health::V1_0::hal_conversion::convertFromHealthConfig;
using android::hardware::health::V1_0::hal_conversion::convertToHealthConfig;
using android::hardware::health::V1_0::hal_conversion::convertFromHealthInfo;
using android::hardware::health::V1_0::hal_conversion::convertToHealthInfo;

using IHealthLegacy = android::hardware::health::V1_0::IHealth;

static android::sp<IHealthLegacy> gHealth_1_0;

static int healthd_board_get_energy_counter(int64_t* energy) {
    if (gHealth_1_0 == nullptr) {
        return NAME_NOT_FOUND;
    }

    Result result = Result::NOT_SUPPORTED;
    gHealth_1_0->energyCounter([energy, &result](Result ret, int64_t energyOut) {
        result = ret;
        *energy = energyOut;
    });

    return result == Result::SUCCESS ? OK : NAME_NOT_FOUND;
}

void healthd_board_init(struct healthd_config* config) {
    gHealth_1_0 = IHealthLegacy::getService();

    if (gHealth_1_0 == nullptr) {
        return;
    }

    HealthConfig halConfig{};
    convertToHealthConfig(config, halConfig);
    gHealth_1_0->init(halConfig, [config](const auto& halConfigOut) {
        convertFromHealthConfig(halConfigOut, config);
        // always redirect energy counter queries
        config->energyCounter = healthd_board_get_energy_counter;
    });
    LOG(INFO) << LOG_TAG << ": redirecting calls to 1.0 health HAL";
}

// TODO(b/68724651): Move this function into healthd_mode_service_2_0_battery_update
// with logthis returned.
int healthd_board_battery_update(struct android::BatteryProperties* props) {
    int logthis = 0;

    if (gHealth_1_0 == nullptr) {
        return logthis;
    }

    HealthInfo info;
    convertToHealthInfo(props, info);
    gHealth_1_0->update(info, [props, &logthis](int32_t ret, const auto& infoOut) {
        logthis = ret;
        convertFromHealthInfo(infoOut, props);
    });

    return logthis;
}

int main() {
    return health_service_main("backup");
}

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

#include "healthd_mode_charger_hidl.h"

#include <android/hardware/health/2.0/types.h>
#include <charger.sysprop.h>
#include <cutils/klog.h>

#include "charger_utils.h"

using android::hardware::health::GetHealthServiceOrDefault;
using android::hardware::health::V2_0::Result;

namespace android {

ChargerHidl::ChargerHidl(const sp<android::hardware::health::V2_1::IHealth>& service)
    : HalHealthLoop("charger", service), charger_(std::make_unique<Charger>(this)) {}

void ChargerHidl::OnHealthInfoChanged(const HealthInfo_2_1& health_info) {
    set_charger_online(health_info);

    charger_->OnHealthInfoChanged(ChargerHealthInfo{
            .battery_level = health_info.legacy.legacy.batteryLevel,
            .battery_status = static_cast<::aidl::android::hardware::health::BatteryStatus>(
                    health_info.legacy.legacy.batteryStatus),
    });

    AdjustWakealarmPeriods(charger_online());
}

std::optional<bool> ChargerHidl::ChargerShouldKeepScreenOn() {
    std::optional<bool> out_screen_on;
    service()->shouldKeepScreenOn([&](Result res, bool screen_on) {
        if (res == Result::SUCCESS) {
            *out_screen_on = screen_on;
        }
    });
    return out_screen_on;
}

bool ChargerHidl::ChargerEnableSuspend() {
    return android::sysprop::ChargerProperties::enable_suspend().value_or(false);
}

}  // namespace android

int healthd_charger_main(int argc, char** argv) {
    int ch;

    while ((ch = getopt(argc, argv, "cr")) != -1) {
        switch (ch) {
            case 'c':
                // -c is now a noop
                break;
            case 'r':
                // -r is now a noop
                break;
            case '?':
            default:
                KLOG_ERROR("charger", "Unrecognized charger option: %c\n", optopt);
                exit(1);
        }
    }

    android::ChargerHidl charger(GetHealthServiceOrDefault());
    return charger.StartLoop();
}

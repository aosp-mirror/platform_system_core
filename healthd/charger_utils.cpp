/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include "charger_utils.h"

#include <android-base/logging.h>
#include <android/hardware/health/2.1/IHealth.h>
#include <health/utils.h>
#include <health2impl/Health.h>

namespace android {
namespace hardware {
namespace health {

sp<V2_1::IHealth> GetHealthServiceOrDefault() {
    // No need to use get_health_service from libhealthhalutils that
    // checks for "backup" instance provided by healthd, since
    // V2_1::implementation::Health does the same thing.
    sp<V2_1::IHealth> service = V2_1::IHealth::getService();
    if (service != nullptr) {
        LOG(INFO) << "Charger uses health HAL service.";
    } else {
        LOG(WARNING) << "Charger uses system defaults.";
        auto config = std::make_unique<healthd_config>();
        InitHealthdConfig(config.get());
        service = new V2_1::implementation::Health(std::move(config));
    }
    return service;
}

}  // namespace health
}  // namespace hardware
}  // namespace android

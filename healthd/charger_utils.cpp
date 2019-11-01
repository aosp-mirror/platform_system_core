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
#include <android/hidl/manager/1.0/IServiceManager.h>
#include <health/utils.h>
#include <health2impl/Health.h>
#include <hidl/ServiceManagement.h>

using android::hardware::getPassthroughServiceManager;
using android::hidl::base::V1_0::IBase;
using android::hidl::manager::V1_0::IServiceManager;

namespace android {
namespace hardware {
namespace health {
sp<V2_1::IHealth> GetPassthroughHealthImpl() {
    // Not using getService() because there is no hwservicemanager in charger mode.
    sp<IServiceManager> pm = getPassthroughServiceManager();
    if (pm == nullptr) {
        LOG(WARNING) << "Cannot get passthrough service manager.";
        return nullptr;
    }
    sp<IBase> base = pm->get(V2_0::IHealth::descriptor, "default");
    if (base == nullptr) {
        LOG(WARNING) << "Cannot find passthrough implementation of health 2.0 HAL for instance "
                        "'default' on the device.";
        return nullptr;
    }
    sp<V2_1::IHealth> service = V2_1::IHealth::castFrom(base);
    if (service == nullptr) {
        LOG(WARNING)
                << "Cannot cast passthrough implementation of health 2.0 HAL to 2.1 for instance "
                   "'default' on the device.";
        return nullptr;
    }
    return service;
}

sp<V2_1::IHealth> GetPassthroughHealth() {
    auto impl = GetPassthroughHealthImpl();
    if (impl == nullptr) {
        LOG(WARNING) << "Charger uses system defaults.";
        auto config = std::make_unique<healthd_config>();
        InitHealthdConfig(config.get());
        impl = new V2_1::implementation::Health(std::move(config));
    }
    return impl;
}

}  // namespace health
}  // namespace hardware
}  // namespace android

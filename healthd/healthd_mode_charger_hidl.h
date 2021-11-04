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

#include <health2impl/HalHealthLoop.h>

#include <charger/healthd_mode_charger.h>

namespace android {

// An implementation of Charger backed by HIDL implementation. Uses HIDL health
// HAL's HalHealthLoop.
class ChargerHidl : public ::android::ChargerConfigurationInterface,
                    public ::android::hardware::health::V2_1::implementation::HalHealthLoop {
    using HalHealthLoop = ::android::hardware::health::V2_1::implementation::HalHealthLoop;
    using HealthInfo_2_1 = android::hardware::health::V2_1::HealthInfo;

  public:
    explicit ChargerHidl(const sp<android::hardware::health::V2_1::IHealth>& service);
    std::optional<bool> ChargerShouldKeepScreenOn() override;
    bool ChargerIsOnline() override { return HalHealthLoop::charger_online(); }
    void ChargerInitConfig(healthd_config* config) override { return HalHealthLoop::Init(config); }
    int ChargerRegisterEvent(int fd, BoundFunction func, EventWakeup wakeup) override {
        return HalHealthLoop::RegisterEvent(fd, func, wakeup);
    }
    bool ChargerEnableSuspend() override;
    // HealthLoop overrides
    void Heartbeat() override { charger_->OnHeartbeat(); }
    int PrepareToWait() override { return charger_->OnPrepareToWait(); }
    void Init(struct healthd_config* config) override { charger_->OnInit(config); }
    // HalHealthLoop overrides
    void OnHealthInfoChanged(const HealthInfo_2_1& health_info) override;

  private:
    sp<android::hardware::health::V2_1::IHealth> service_;
    std::unique_ptr<Charger> charger_;
};

}  // namespace android

int healthd_charger_main(int argc, char** argv);

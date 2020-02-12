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

#pragma once

#include <linux/input.h>

#include <memory>
#include <vector>

#include <android/hardware/health/2.0/IHealthInfoCallback.h>
#include <android/hardware/health/2.1/IHealth.h>
#include <health2impl/HalHealthLoop.h>

#include "animation.h"

class GRSurface;
class HealthdDraw;

namespace android {
struct key_state {
    bool pending;
    bool down;
    int64_t timestamp;
};

class Charger : public ::android::hardware::health::V2_1::implementation::HalHealthLoop {
  public:
    using HealthInfo_1_0 = android::hardware::health::V1_0::HealthInfo;
    using HealthInfo_2_1 = android::hardware::health::V2_1::HealthInfo;

    Charger(const sp<android::hardware::health::V2_1::IHealth>& service);
    ~Charger();

  protected:
    // HealthLoop overrides.
    void Heartbeat() override;
    int PrepareToWait() override;
    void Init(struct healthd_config* config) override;
    // HalHealthLoop overrides
    void OnHealthInfoChanged(const HealthInfo_2_1& health_info) override;

  private:
    void InitDefaultAnimationFrames();
    void UpdateScreenState(int64_t now);
    int SetKeyCallback(int code, int value);
    void UpdateInputState(input_event* ev);
    void SetNextKeyCheck(key_state* key, int64_t timeout);
    void ProcessKey(int code, int64_t now);
    void HandleInputState(int64_t now);
    void HandlePowerSupplyState(int64_t now);
    int InputCallback(int fd, unsigned int epevents);
    void InitAnimation();

    bool have_battery_state_ = false;
    bool screen_blanked_ = false;
    int64_t next_screen_transition_ = 0;
    int64_t next_key_check_ = 0;
    int64_t next_pwr_check_ = 0;
    int64_t wait_batt_level_timestamp_ = 0;

    key_state keys_[KEY_MAX + 1] = {};

    animation batt_anim_;
    GRSurface* surf_unknown_ = nullptr;
    int boot_min_cap_ = 0;

    HealthInfo_1_0 health_info_ = {};
    std::unique_ptr<HealthdDraw> healthd_draw_;
    std::vector<animation::frame> owned_frames_;
};
}  // namespace android

int healthd_charger_main(int argc, char** argv);

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
#include <optional>
#include <vector>

#include <aidl/android/hardware/health/BatteryStatus.h>
#include <health/HealthLoop.h>
#include <healthd/healthd.h>

#include "animation.h"

class GRSurface;
class HealthdDraw;

namespace android {
struct key_state {
    bool pending;
    bool down;
    int64_t timestamp;
};

// Health info that interests charger
struct ChargerHealthInfo {
    int32_t battery_level;
    aidl::android::hardware::health::BatteryStatus battery_status;
};

enum DirectRenderManager {
    DRM_INNER,
    DRM_OUTER,
};

enum SrceenSwitch {
    SCREEN_SWITCH_DEFAULT,
    SCREEN_SWITCH_DISABLE,
    SCREEN_SWITCH_ENABLE,
};

// Configuration interface for charger. This includes:
// - HalHealthLoop APIs that interests charger.
// - configuration values that used to be provided by sysprops
class ChargerConfigurationInterface {
  public:
    virtual ~ChargerConfigurationInterface() = default;
    // HalHealthLoop related APIs
    virtual std::optional<bool> ChargerShouldKeepScreenOn() = 0;
    virtual bool ChargerIsOnline() = 0;
    virtual void ChargerInitConfig(healthd_config* config) = 0;
    using BoundFunction =
            std::function<void(android::hardware::health::HealthLoop*, uint32_t /* epevents */)>;
    virtual int ChargerRegisterEvent(int fd, BoundFunction func, EventWakeup wakeup) = 0;

    // Other configuration values
    virtual bool ChargerEnableSuspend() = 0;
};

// charger UI
class Charger {
  public:
    explicit Charger(ChargerConfigurationInterface* configuration);
    virtual ~Charger();

    // Hooks for ChargerConfigurationInterface
    void OnHeartbeat();
    int OnPrepareToWait();
    // |cookie| is passed to ChargerConfigurationInterface::ChargerInitConfig
    void OnInit(struct healthd_config* config);
    void OnHealthInfoChanged(const ChargerHealthInfo& health_info);

  protected:
    // Allowed to be mocked for testing.
    virtual int CreateDisplaySurface(const std::string& name, GRSurface** surface);
    virtual int CreateMultiDisplaySurface(const std::string& name, int* frames, int* fps,
                                          GRSurface*** surface);

  private:
    void InitDefaultAnimationFrames();
    void UpdateScreenState(int64_t now);
    int SetKeyCallback(int code, int value);
    int SetSwCallback(int code, int value);
    void UpdateInputState(input_event* ev);
    void SetNextKeyCheck(key_state* key, int64_t timeout);
    void ProcessKey(int code, int64_t now);
    void ProcessHallSensor(int code);
    void HandleInputState(int64_t now);
    void HandlePowerSupplyState(int64_t now);
    int InputCallback(int fd, unsigned int epevents);
    void InitHealthdDraw();
    void InitAnimation();
    int RequestEnableSuspend();
    int RequestDisableSuspend();
    void BlankSecScreen();

    bool have_battery_state_ = false;
    bool screen_blanked_ = false;
    bool init_screen_ = false;
    int64_t next_screen_transition_ = 0;
    int64_t next_key_check_ = 0;
    int64_t next_pwr_check_ = 0;
    int64_t wait_batt_level_timestamp_ = 0;

    DirectRenderManager drm_;
    SrceenSwitch screen_switch_;

    key_state keys_[KEY_MAX + 1] = {};

    animation batt_anim_;
    GRSurface* surf_unknown_ = nullptr;
    int boot_min_cap_ = 0;

    ChargerHealthInfo health_info_ = {};
    std::unique_ptr<HealthdDraw> healthd_draw_;
    std::vector<animation::frame> owned_frames_;

    ChargerConfigurationInterface* configuration_;
};
}  // namespace android

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

#ifndef HEALTHD_BATTERYMONITOR_H
#define HEALTHD_BATTERYMONITOR_H

#include <memory>
#include <optional>

#include <batteryservice/BatteryService.h>
#include <utils/String8.h>
#include <utils/Vector.h>

#include <healthd/healthd.h>

namespace aidl::android::hardware::health {
class HealthInfo;
}  // namespace aidl::android::hardware::health

namespace android {
namespace hardware {
namespace health {
namespace V1_0 {
struct HealthInfo;
}  // namespace V1_0
namespace V2_0 {
struct HealthInfo;
}  // namespace V2_0
namespace V2_1 {
struct HealthInfo;
}  // namespace V2_1
}  // namespace health
}  // namespace hardware

class BatteryMonitor {
  public:

    enum PowerSupplyType {
        ANDROID_POWER_SUPPLY_TYPE_UNKNOWN = 0,
        ANDROID_POWER_SUPPLY_TYPE_AC,
        ANDROID_POWER_SUPPLY_TYPE_USB,
        ANDROID_POWER_SUPPLY_TYPE_WIRELESS,
        ANDROID_POWER_SUPPLY_TYPE_BATTERY,
        ANDROID_POWER_SUPPLY_TYPE_DOCK
    };

    enum BatteryHealthStatus {
        BH_UNKNOWN = -1,
        BH_NOMINAL,
        BH_MARGINAL,
        BH_NEEDS_REPLACEMENT,
        BH_FAILED,
        BH_NOT_AVAILABLE,
        BH_INCONSISTENT,
    };

    BatteryMonitor();
    ~BatteryMonitor();
    void init(struct healthd_config *hc);
    int getChargeStatus();
    status_t getProperty(int id, struct BatteryProperty *val);
    void dumpState(int fd);

    android::hardware::health::V1_0::HealthInfo getHealthInfo_1_0() const;
    android::hardware::health::V2_0::HealthInfo getHealthInfo_2_0() const;
    android::hardware::health::V2_1::HealthInfo getHealthInfo_2_1() const;
    const aidl::android::hardware::health::HealthInfo& getHealthInfo() const;

    void updateValues(void);
    void logValues(void);
    bool isChargerOnline();

    int setChargingPolicy(int value);
    int getChargingPolicy();
    int getBatteryHealthData(int id);

    status_t getSerialNumber(std::optional<std::string>* out);

    static void logValues(const android::hardware::health::V2_1::HealthInfo& health_info,
                          const struct healthd_config& healthd_config);

  private:
    struct healthd_config *mHealthdConfig;
    Vector<String8> mChargerNames;
    bool mBatteryDevicePresent;
    int mBatteryFixedCapacity;
    int mBatteryFixedTemperature;
    int mBatteryHealthStatus;
    std::unique_ptr<aidl::android::hardware::health::HealthInfo> mHealthInfo;
};

}; // namespace android

#endif // HEALTHD_BATTERY_MONTIOR_H

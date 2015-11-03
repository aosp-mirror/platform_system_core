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

#include <batteryservice/BatteryService.h>
#include <binder/IInterface.h>
#include <utils/String8.h>
#include <utils/Vector.h>

#include "healthd.h"

namespace android {

class BatteryMonitor {
  public:

    enum PowerSupplyType {
        ANDROID_POWER_SUPPLY_TYPE_UNKNOWN = 0,
        ANDROID_POWER_SUPPLY_TYPE_AC,
        ANDROID_POWER_SUPPLY_TYPE_USB,
        ANDROID_POWER_SUPPLY_TYPE_WIRELESS,
        ANDROID_POWER_SUPPLY_TYPE_BATTERY
    };

    void init(struct healthd_config *hc);
    bool update(void);
    status_t getProperty(int id, struct BatteryProperty *val);
    void dumpState(int fd);

  private:
    struct healthd_config *mHealthdConfig;
    Vector<String8> mChargerNames;
    bool mBatteryDevicePresent;
    bool mAlwaysPluggedDevice;
    int mBatteryFixedCapacity;
    int mBatteryFixedTemperature;
    struct BatteryProperties props;

    int getBatteryStatus(const char* status);
    int getBatteryHealth(const char* status);
    int readFromFile(const String8& path, char* buf, size_t size);
    PowerSupplyType readPowerSupplyType(const String8& path);
    bool getBooleanField(const String8& path);
    int getIntField(const String8& path);
};

}; // namespace android

#endif // HEALTHD_BATTERY_MONTIOR_H

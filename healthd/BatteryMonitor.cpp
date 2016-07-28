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

#define LOG_TAG "healthd"

#include <healthd/healthd.h>
#include <healthd/BatteryMonitor.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <memory>
#include <optional>

#include <android-base/file.h>
#include <android-base/parseint.h>
#include <android-base/strings.h>
#include <android/hardware/health/2.1/types.h>
#include <batteryservice/BatteryService.h>
#include <cutils/klog.h>
#include <cutils/properties.h>
#include <utils/Errors.h>
#include <utils/String8.h>
#include <utils/Vector.h>

#define POWER_SUPPLY_SUBSYSTEM "power_supply"
#define POWER_SUPPLY_SYSFS_PATH "/sys/class/" POWER_SUPPLY_SUBSYSTEM
#define FAKE_BATTERY_CAPACITY 42
#define FAKE_BATTERY_TEMPERATURE 424
#define MILLION 1.0e6
#define DEFAULT_VBUS_VOLTAGE 5000000

using HealthInfo_1_0 = android::hardware::health::V1_0::HealthInfo;
using HealthInfo_2_0 = android::hardware::health::V2_0::HealthInfo;
using HealthInfo_2_1 = android::hardware::health::V2_1::HealthInfo;
using android::hardware::health::V1_0::BatteryHealth;
using android::hardware::health::V1_0::BatteryStatus;
using android::hardware::health::V2_1::BatteryCapacityLevel;
using android::hardware::health::V2_1::Constants;

namespace android {

template <typename T>
struct SysfsStringEnumMap {
    const char* s;
    T val;
};

template <typename T>
static std::optional<T> mapSysfsString(const char* str, SysfsStringEnumMap<T> map[]) {
    for (int i = 0; map[i].s; i++)
        if (!strcmp(str, map[i].s))
            return map[i].val;

    return std::nullopt;
}

static void initHealthInfo(HealthInfo_2_1* health_info_2_1) {
    *health_info_2_1 = HealthInfo_2_1{};

    // HIDL enum values are zero initialized, so they need to be initialized
    // properly.
    health_info_2_1->batteryCapacityLevel = BatteryCapacityLevel::UNSUPPORTED;
    health_info_2_1->batteryChargeTimeToFullNowSeconds =
            (int64_t)Constants::BATTERY_CHARGE_TIME_TO_FULL_NOW_SECONDS_UNSUPPORTED;
    auto* props = &health_info_2_1->legacy.legacy;
    props->batteryStatus = BatteryStatus::UNKNOWN;
    props->batteryHealth = BatteryHealth::UNKNOWN;
}

BatteryMonitor::BatteryMonitor()
    : mHealthdConfig(nullptr),
      mBatteryDevicePresent(false),
      mBatteryFixedCapacity(0),
      mBatteryFixedTemperature(0),
      mHealthInfo(std::make_unique<HealthInfo_2_1>()) {
    initHealthInfo(mHealthInfo.get());
}

BatteryMonitor::~BatteryMonitor() {}

const HealthInfo_1_0& BatteryMonitor::getHealthInfo_1_0() const {
    return getHealthInfo_2_0().legacy;
}

const HealthInfo_2_0& BatteryMonitor::getHealthInfo_2_0() const {
    return getHealthInfo_2_1().legacy;
}

const HealthInfo_2_1& BatteryMonitor::getHealthInfo_2_1() const {
    return *mHealthInfo;
}

BatteryStatus getBatteryStatus(const char* status) {
    static SysfsStringEnumMap<BatteryStatus> batteryStatusMap[] = {
            {"Unknown", BatteryStatus::UNKNOWN},
            {"Charging", BatteryStatus::CHARGING},
            {"Discharging", BatteryStatus::DISCHARGING},
            {"Not charging", BatteryStatus::NOT_CHARGING},
            {"Full", BatteryStatus::FULL},
            {NULL, BatteryStatus::UNKNOWN},
    };

    auto ret = mapSysfsString(status, batteryStatusMap);
    if (!ret) {
        KLOG_WARNING(LOG_TAG, "Unknown battery status '%s'\n", status);
        *ret = BatteryStatus::UNKNOWN;
    }

    return *ret;
}

BatteryCapacityLevel getBatteryCapacityLevel(const char* capacityLevel) {
    static SysfsStringEnumMap<BatteryCapacityLevel> batteryCapacityLevelMap[] = {
            {"Unknown", BatteryCapacityLevel::UNKNOWN},
            {"Critical", BatteryCapacityLevel::CRITICAL},
            {"Low", BatteryCapacityLevel::LOW},
            {"Normal", BatteryCapacityLevel::NORMAL},
            {"High", BatteryCapacityLevel::HIGH},
            {"Full", BatteryCapacityLevel::FULL},
            {NULL, BatteryCapacityLevel::UNSUPPORTED},
    };

    auto ret = mapSysfsString(capacityLevel, batteryCapacityLevelMap);
    if (!ret) {
        KLOG_WARNING(LOG_TAG, "Unsupported battery capacity level '%s'\n", capacityLevel);
        *ret = BatteryCapacityLevel::UNSUPPORTED;
    }

    return *ret;
}

BatteryHealth getBatteryHealth(const char* status) {
    static SysfsStringEnumMap<BatteryHealth> batteryHealthMap[] = {
            {"Unknown", BatteryHealth::UNKNOWN},
            {"Good", BatteryHealth::GOOD},
            {"Overheat", BatteryHealth::OVERHEAT},
            {"Dead", BatteryHealth::DEAD},
            {"Over voltage", BatteryHealth::OVER_VOLTAGE},
            {"Unspecified failure", BatteryHealth::UNSPECIFIED_FAILURE},
            {"Cold", BatteryHealth::COLD},
            // battery health values from JEITA spec
            {"Warm", BatteryHealth::GOOD},
            {"Cool", BatteryHealth::GOOD},
            {"Hot", BatteryHealth::OVERHEAT},
            {NULL, BatteryHealth::UNKNOWN},
    };

    auto ret = mapSysfsString(status, batteryHealthMap);
    if (!ret) {
        KLOG_WARNING(LOG_TAG, "Unknown battery health '%s'\n", status);
        *ret = BatteryHealth::UNKNOWN;
    }

    return *ret;
}

int BatteryMonitor::readFromFile(const String8& path, std::string* buf) {
    if (android::base::ReadFileToString(path.c_str(), buf)) {
        *buf = android::base::Trim(*buf);
    }
    return buf->length();
}

BatteryMonitor::PowerSupplyType BatteryMonitor::readPowerSupplyType(const String8& path) {
    static SysfsStringEnumMap<int> supplyTypeMap[] = {
            {"Unknown", ANDROID_POWER_SUPPLY_TYPE_UNKNOWN},
            {"Battery", ANDROID_POWER_SUPPLY_TYPE_BATTERY},
            {"UPS", ANDROID_POWER_SUPPLY_TYPE_AC},
            {"Mains", ANDROID_POWER_SUPPLY_TYPE_AC},
            {"USB", ANDROID_POWER_SUPPLY_TYPE_USB},
            {"USB_DCP", ANDROID_POWER_SUPPLY_TYPE_AC},
            {"USB_HVDCP", ANDROID_POWER_SUPPLY_TYPE_AC},
            {"USB_CDP", ANDROID_POWER_SUPPLY_TYPE_AC},
            {"USB_ACA", ANDROID_POWER_SUPPLY_TYPE_AC},
            {"USB_C", ANDROID_POWER_SUPPLY_TYPE_AC},
            {"USB_PD", ANDROID_POWER_SUPPLY_TYPE_AC},
            {"USB_PD_DRP", ANDROID_POWER_SUPPLY_TYPE_USB},
            {"Wireless", ANDROID_POWER_SUPPLY_TYPE_WIRELESS},
            {"DASH", ANDROID_POWER_SUPPLY_TYPE_AC},
            {NULL, 0},
    };
    std::string buf;

    if (readFromFile(path, &buf) <= 0)
        return ANDROID_POWER_SUPPLY_TYPE_UNKNOWN;

    auto ret = mapSysfsString(buf.c_str(), supplyTypeMap);
    if (!ret) {
        KLOG_WARNING(LOG_TAG, "Unknown power supply type '%s'\n", buf.c_str());
        *ret = ANDROID_POWER_SUPPLY_TYPE_UNKNOWN;
    }

    return static_cast<BatteryMonitor::PowerSupplyType>(*ret);
}

bool BatteryMonitor::getBooleanField(const String8& path) {
    std::string buf;
    bool value = false;

    if (readFromFile(path, &buf) > 0)
        if (buf[0] != '0')
            value = true;

    return value;
}

int BatteryMonitor::getIntField(const String8& path) {
    std::string buf;
    int value = 0;

    if (readFromFile(path, &buf) > 0)
        android::base::ParseInt(buf, &value);

    return value;
}

bool BatteryMonitor::isScopedPowerSupply(const char* name) {
    constexpr char kScopeDevice[] = "Device";

    String8 path;
    path.appendFormat("%s/%s/scope", POWER_SUPPLY_SYSFS_PATH, name);
    std::string scope;
    return (readFromFile(path, &scope) > 0 && scope == kScopeDevice);
}

void BatteryMonitor::updateValues(void) {
    initHealthInfo(mHealthInfo.get());

    HealthInfo_1_0& props = mHealthInfo->legacy.legacy;

    if (!mHealthdConfig->batteryPresentPath.isEmpty())
        props.batteryPresent = getBooleanField(mHealthdConfig->batteryPresentPath);
    else
        props.batteryPresent = mBatteryDevicePresent;

    props.batteryLevel = mBatteryFixedCapacity ?
        mBatteryFixedCapacity :
        getIntField(mHealthdConfig->batteryCapacityPath);
    props.batteryVoltage = getIntField(mHealthdConfig->batteryVoltagePath) / 1000;

    if (!mHealthdConfig->batteryCurrentNowPath.isEmpty())
        props.batteryCurrent = getIntField(mHealthdConfig->batteryCurrentNowPath);

    if (!mHealthdConfig->batteryFullChargePath.isEmpty())
        props.batteryFullCharge = getIntField(mHealthdConfig->batteryFullChargePath);

    if (!mHealthdConfig->batteryCycleCountPath.isEmpty())
        props.batteryCycleCount = getIntField(mHealthdConfig->batteryCycleCountPath);

    if (!mHealthdConfig->batteryChargeCounterPath.isEmpty())
        props.batteryChargeCounter = getIntField(mHealthdConfig->batteryChargeCounterPath);

    if (!mHealthdConfig->batteryCurrentAvgPath.isEmpty())
        mHealthInfo->legacy.batteryCurrentAverage =
                getIntField(mHealthdConfig->batteryCurrentAvgPath);

    if (!mHealthdConfig->batteryChargeTimeToFullNowPath.isEmpty())
        mHealthInfo->batteryChargeTimeToFullNowSeconds =
                getIntField(mHealthdConfig->batteryChargeTimeToFullNowPath);

    if (!mHealthdConfig->batteryFullChargeDesignCapacityUahPath.isEmpty())
        mHealthInfo->batteryFullChargeDesignCapacityUah =
                getIntField(mHealthdConfig->batteryFullChargeDesignCapacityUahPath);

    props.batteryTemperature = mBatteryFixedTemperature ?
        mBatteryFixedTemperature :
        getIntField(mHealthdConfig->batteryTemperaturePath);

    std::string buf;

    if (readFromFile(mHealthdConfig->batteryCapacityLevelPath, &buf) > 0)
        mHealthInfo->batteryCapacityLevel = getBatteryCapacityLevel(buf.c_str());

    if (readFromFile(mHealthdConfig->batteryStatusPath, &buf) > 0)
        props.batteryStatus = getBatteryStatus(buf.c_str());

    if (readFromFile(mHealthdConfig->batteryHealthPath, &buf) > 0)
        props.batteryHealth = getBatteryHealth(buf.c_str());

    if (readFromFile(mHealthdConfig->batteryTechnologyPath, &buf) > 0)
        props.batteryTechnology = String8(buf.c_str());

    double MaxPower = 0;

    for (size_t i = 0; i < mChargerNames.size(); i++) {
        String8 path;
        path.appendFormat("%s/%s/online", POWER_SUPPLY_SYSFS_PATH,
                          mChargerNames[i].string());
        if (getIntField(path)) {
            path.clear();
            path.appendFormat("%s/%s/type", POWER_SUPPLY_SYSFS_PATH,
                              mChargerNames[i].string());
            switch(readPowerSupplyType(path)) {
            case ANDROID_POWER_SUPPLY_TYPE_AC:
                props.chargerAcOnline = true;
                break;
            case ANDROID_POWER_SUPPLY_TYPE_USB:
                props.chargerUsbOnline = true;
                break;
            case ANDROID_POWER_SUPPLY_TYPE_WIRELESS:
                props.chargerWirelessOnline = true;
                break;
            default:
                KLOG_WARNING(LOG_TAG, "%s: Unknown power supply type\n",
                             mChargerNames[i].string());
            }
            path.clear();
            path.appendFormat("%s/%s/current_max", POWER_SUPPLY_SYSFS_PATH,
                              mChargerNames[i].string());
            int ChargingCurrent =
                    (access(path.string(), R_OK) == 0) ? getIntField(path) : 0;

            path.clear();
            path.appendFormat("%s/%s/voltage_max", POWER_SUPPLY_SYSFS_PATH,
                              mChargerNames[i].string());

            int ChargingVoltage =
                (access(path.string(), R_OK) == 0) ? getIntField(path) :
                DEFAULT_VBUS_VOLTAGE;

            double power = ((double)ChargingCurrent / MILLION) *
                           ((double)ChargingVoltage / MILLION);
            if (MaxPower < power) {
                props.maxChargingCurrent = ChargingCurrent;
                props.maxChargingVoltage = ChargingVoltage;
                MaxPower = power;
            }
        }
    }
}

void BatteryMonitor::logValues(void) {
    logValues(*mHealthInfo, *mHealthdConfig);
}

void BatteryMonitor::logValues(const android::hardware::health::V2_1::HealthInfo& health_info,
                               const struct healthd_config& healthd_config) {
    char dmesgline[256];
    size_t len;
    const HealthInfo_1_0& props = health_info.legacy.legacy;
    if (props.batteryPresent) {
        snprintf(dmesgline, sizeof(dmesgline), "battery l=%d v=%d t=%s%d.%d h=%d st=%d",
                 props.batteryLevel, props.batteryVoltage, props.batteryTemperature < 0 ? "-" : "",
                 abs(props.batteryTemperature / 10), abs(props.batteryTemperature % 10),
                 props.batteryHealth, props.batteryStatus);

        len = strlen(dmesgline);
        if (!healthd_config.batteryCurrentNowPath.isEmpty()) {
            len += snprintf(dmesgline + len, sizeof(dmesgline) - len, " c=%d",
                            props.batteryCurrent);
        }

        if (!healthd_config.batteryFullChargePath.isEmpty()) {
            len += snprintf(dmesgline + len, sizeof(dmesgline) - len, " fc=%d",
                            props.batteryFullCharge);
        }

        if (!healthd_config.batteryCycleCountPath.isEmpty()) {
            len += snprintf(dmesgline + len, sizeof(dmesgline) - len, " cc=%d",
                            props.batteryCycleCount);
        }
    } else {
        len = snprintf(dmesgline, sizeof(dmesgline), "battery none");
    }

    snprintf(dmesgline + len, sizeof(dmesgline) - len, " chg=%s%s%s",
             props.chargerAcOnline ? "a" : "", props.chargerUsbOnline ? "u" : "",
             props.chargerWirelessOnline ? "w" : "");

    KLOG_WARNING(LOG_TAG, "%s\n", dmesgline);
}

bool BatteryMonitor::isChargerOnline() {
    const HealthInfo_1_0& props = mHealthInfo->legacy.legacy;
    return props.chargerAcOnline | props.chargerUsbOnline |
            props.chargerWirelessOnline;
}

int BatteryMonitor::getChargeStatus() {
    BatteryStatus result = BatteryStatus::UNKNOWN;
    if (!mHealthdConfig->batteryStatusPath.isEmpty()) {
        std::string buf;
        if (readFromFile(mHealthdConfig->batteryStatusPath, &buf) > 0)
            result = getBatteryStatus(buf.c_str());
    }
    return static_cast<int>(result);
}

status_t BatteryMonitor::getProperty(int id, struct BatteryProperty *val) {
    status_t ret = BAD_VALUE;
    std::string buf;

    val->valueInt64 = LONG_MIN;

    switch(id) {
    case BATTERY_PROP_CHARGE_COUNTER:
        if (!mHealthdConfig->batteryChargeCounterPath.isEmpty()) {
            val->valueInt64 =
                getIntField(mHealthdConfig->batteryChargeCounterPath);
            ret = OK;
        } else {
            ret = NAME_NOT_FOUND;
        }
        break;

    case BATTERY_PROP_CURRENT_NOW:
        if (!mHealthdConfig->batteryCurrentNowPath.isEmpty()) {
            val->valueInt64 =
                getIntField(mHealthdConfig->batteryCurrentNowPath);
            ret = OK;
        } else {
            ret = NAME_NOT_FOUND;
        }
        break;

    case BATTERY_PROP_CURRENT_AVG:
        if (!mHealthdConfig->batteryCurrentAvgPath.isEmpty()) {
            val->valueInt64 =
                getIntField(mHealthdConfig->batteryCurrentAvgPath);
            ret = OK;
        } else {
            ret = NAME_NOT_FOUND;
        }
        break;

    case BATTERY_PROP_CAPACITY:
        if (!mHealthdConfig->batteryCapacityPath.isEmpty()) {
            val->valueInt64 =
                getIntField(mHealthdConfig->batteryCapacityPath);
            ret = OK;
        } else {
            ret = NAME_NOT_FOUND;
        }
        break;

    case BATTERY_PROP_ENERGY_COUNTER:
        if (mHealthdConfig->energyCounter) {
            ret = mHealthdConfig->energyCounter(&val->valueInt64);
        } else {
            ret = NAME_NOT_FOUND;
        }
        break;

    case BATTERY_PROP_BATTERY_STATUS:
        val->valueInt64 = getChargeStatus();
        ret = OK;
        break;

    default:
        break;
    }

    return ret;
}

void BatteryMonitor::dumpState(int fd) {
    int v;
    char vs[128];
    const HealthInfo_1_0& props = mHealthInfo->legacy.legacy;

    snprintf(vs, sizeof(vs), "ac: %d usb: %d wireless: %d current_max: %d voltage_max: %d\n",
             props.chargerAcOnline, props.chargerUsbOnline,
             props.chargerWirelessOnline, props.maxChargingCurrent,
             props.maxChargingVoltage);
    write(fd, vs, strlen(vs));
    snprintf(vs, sizeof(vs), "status: %d health: %d present: %d\n",
             props.batteryStatus, props.batteryHealth, props.batteryPresent);
    write(fd, vs, strlen(vs));
    snprintf(vs, sizeof(vs), "level: %d voltage: %d temp: %d\n",
             props.batteryLevel, props.batteryVoltage,
             props.batteryTemperature);
    write(fd, vs, strlen(vs));

    if (!mHealthdConfig->batteryCurrentNowPath.isEmpty()) {
        v = getIntField(mHealthdConfig->batteryCurrentNowPath);
        snprintf(vs, sizeof(vs), "current now: %d\n", v);
        write(fd, vs, strlen(vs));
    }

    if (!mHealthdConfig->batteryCurrentAvgPath.isEmpty()) {
        v = getIntField(mHealthdConfig->batteryCurrentAvgPath);
        snprintf(vs, sizeof(vs), "current avg: %d\n", v);
        write(fd, vs, strlen(vs));
    }

    if (!mHealthdConfig->batteryChargeCounterPath.isEmpty()) {
        v = getIntField(mHealthdConfig->batteryChargeCounterPath);
        snprintf(vs, sizeof(vs), "charge counter: %d\n", v);
        write(fd, vs, strlen(vs));
    }

    if (!mHealthdConfig->batteryCurrentNowPath.isEmpty()) {
        snprintf(vs, sizeof(vs), "current now: %d\n", props.batteryCurrent);
        write(fd, vs, strlen(vs));
    }

    if (!mHealthdConfig->batteryCycleCountPath.isEmpty()) {
        snprintf(vs, sizeof(vs), "cycle count: %d\n", props.batteryCycleCount);
        write(fd, vs, strlen(vs));
    }

    if (!mHealthdConfig->batteryFullChargePath.isEmpty()) {
        snprintf(vs, sizeof(vs), "Full charge: %d\n", props.batteryFullCharge);
        write(fd, vs, strlen(vs));
    }
}

void BatteryMonitor::init(struct healthd_config *hc) {
    String8 path;
    char pval[PROPERTY_VALUE_MAX];

    mHealthdConfig = hc;
    std::unique_ptr<DIR, decltype(&closedir)> dir(opendir(POWER_SUPPLY_SYSFS_PATH), closedir);
    if (dir == NULL) {
        KLOG_ERROR(LOG_TAG, "Could not open %s\n", POWER_SUPPLY_SYSFS_PATH);
    } else {
        struct dirent* entry;

        while ((entry = readdir(dir.get()))) {
            const char* name = entry->d_name;
            std::vector<String8>::iterator itIgnoreName;

            if (!strcmp(name, ".") || !strcmp(name, ".."))
                continue;

            itIgnoreName = find(hc->ignorePowerSupplyNames.begin(),
                                hc->ignorePowerSupplyNames.end(), String8(name));
            if (itIgnoreName != hc->ignorePowerSupplyNames.end())
                continue;

            // Look for "type" file in each subdirectory
            path.clear();
            path.appendFormat("%s/%s/type", POWER_SUPPLY_SYSFS_PATH, name);
            switch(readPowerSupplyType(path)) {
            case ANDROID_POWER_SUPPLY_TYPE_AC:
            case ANDROID_POWER_SUPPLY_TYPE_USB:
            case ANDROID_POWER_SUPPLY_TYPE_WIRELESS:
                path.clear();
                path.appendFormat("%s/%s/online", POWER_SUPPLY_SYSFS_PATH, name);
                if (access(path.string(), R_OK) == 0)
                    mChargerNames.add(String8(name));
                break;

            case ANDROID_POWER_SUPPLY_TYPE_BATTERY:
                // Some devices expose the battery status of sub-component like
                // stylus. Such a device-scoped battery info needs to be skipped
                // in BatteryMonitor, which is intended to report the status of
                // the battery supplying the power to the whole system.
                if (isScopedPowerSupply(name)) continue;
                mBatteryDevicePresent = true;

                if (mHealthdConfig->batteryStatusPath.isEmpty()) {
                    path.clear();
                    path.appendFormat("%s/%s/status", POWER_SUPPLY_SYSFS_PATH,
                                      name);
                    if (access(path, R_OK) == 0)
                        mHealthdConfig->batteryStatusPath = path;
                }

                if (mHealthdConfig->batteryHealthPath.isEmpty()) {
                    path.clear();
                    path.appendFormat("%s/%s/health", POWER_SUPPLY_SYSFS_PATH,
                                      name);
                    if (access(path, R_OK) == 0)
                        mHealthdConfig->batteryHealthPath = path;
                }

                if (mHealthdConfig->batteryPresentPath.isEmpty()) {
                    path.clear();
                    path.appendFormat("%s/%s/present", POWER_SUPPLY_SYSFS_PATH,
                                      name);
                    if (access(path, R_OK) == 0)
                        mHealthdConfig->batteryPresentPath = path;
                }

                if (mHealthdConfig->batteryCapacityPath.isEmpty()) {
                    path.clear();
                    path.appendFormat("%s/%s/capacity", POWER_SUPPLY_SYSFS_PATH,
                                      name);
                    if (access(path, R_OK) == 0)
                        mHealthdConfig->batteryCapacityPath = path;
                }

                if (mHealthdConfig->batteryVoltagePath.isEmpty()) {
                    path.clear();
                    path.appendFormat("%s/%s/voltage_now",
                                      POWER_SUPPLY_SYSFS_PATH, name);
                    if (access(path, R_OK) == 0) {
                        mHealthdConfig->batteryVoltagePath = path;
                    }
                }

                if (mHealthdConfig->batteryFullChargePath.isEmpty()) {
                    path.clear();
                    path.appendFormat("%s/%s/charge_full",
                                      POWER_SUPPLY_SYSFS_PATH, name);
                    if (access(path, R_OK) == 0)
                        mHealthdConfig->batteryFullChargePath = path;
                }

                if (mHealthdConfig->batteryCurrentNowPath.isEmpty()) {
                    path.clear();
                    path.appendFormat("%s/%s/current_now",
                                      POWER_SUPPLY_SYSFS_PATH, name);
                    if (access(path, R_OK) == 0)
                        mHealthdConfig->batteryCurrentNowPath = path;
                }

                if (mHealthdConfig->batteryCycleCountPath.isEmpty()) {
                    path.clear();
                    path.appendFormat("%s/%s/cycle_count",
                                      POWER_SUPPLY_SYSFS_PATH, name);
                    if (access(path, R_OK) == 0)
                        mHealthdConfig->batteryCycleCountPath = path;
                }

                if (mHealthdConfig->batteryCapacityLevelPath.isEmpty()) {
                    path.clear();
                    path.appendFormat("%s/%s/capacity_level", POWER_SUPPLY_SYSFS_PATH, name);
                    if (access(path, R_OK) == 0) mHealthdConfig->batteryCapacityLevelPath = path;
                }

                if (mHealthdConfig->batteryChargeTimeToFullNowPath.isEmpty()) {
                    path.clear();
                    path.appendFormat("%s/%s/time_to_full_now", POWER_SUPPLY_SYSFS_PATH, name);
                    if (access(path, R_OK) == 0)
                        mHealthdConfig->batteryChargeTimeToFullNowPath = path;
                }

                if (mHealthdConfig->batteryFullChargeDesignCapacityUahPath.isEmpty()) {
                    path.clear();
                    path.appendFormat("%s/%s/charge_full_design", POWER_SUPPLY_SYSFS_PATH, name);
                    if (access(path, R_OK) == 0)
                        mHealthdConfig->batteryFullChargeDesignCapacityUahPath = path;
                }

                if (mHealthdConfig->batteryCurrentAvgPath.isEmpty()) {
                    path.clear();
                    path.appendFormat("%s/%s/current_avg",
                                      POWER_SUPPLY_SYSFS_PATH, name);
                    if (access(path, R_OK) == 0)
                        mHealthdConfig->batteryCurrentAvgPath = path;
                }

                if (mHealthdConfig->batteryChargeCounterPath.isEmpty()) {
                    path.clear();
                    path.appendFormat("%s/%s/charge_counter",
                                      POWER_SUPPLY_SYSFS_PATH, name);
                    if (access(path, R_OK) == 0)
                        mHealthdConfig->batteryChargeCounterPath = path;
                }

                if (mHealthdConfig->batteryTemperaturePath.isEmpty()) {
                    path.clear();
                    path.appendFormat("%s/%s/temp", POWER_SUPPLY_SYSFS_PATH,
                                      name);
                    if (access(path, R_OK) == 0) {
                        mHealthdConfig->batteryTemperaturePath = path;
                    }
                }

                if (mHealthdConfig->batteryTechnologyPath.isEmpty()) {
                    path.clear();
                    path.appendFormat("%s/%s/technology",
                                      POWER_SUPPLY_SYSFS_PATH, name);
                    if (access(path, R_OK) == 0)
                        mHealthdConfig->batteryTechnologyPath = path;
                }

                break;

            case ANDROID_POWER_SUPPLY_TYPE_UNKNOWN:
                break;
            }
        }
    }

    // Typically the case for devices which do not have a battery and
    // and are always plugged into AC mains.
    if (!mBatteryDevicePresent) {
        KLOG_WARNING(LOG_TAG, "No battery devices found\n");
        hc->periodic_chores_interval_fast = -1;
        hc->periodic_chores_interval_slow = -1;
    } else {
        if (mHealthdConfig->batteryStatusPath.isEmpty())
            KLOG_WARNING(LOG_TAG, "BatteryStatusPath not found\n");
        if (mHealthdConfig->batteryHealthPath.isEmpty())
            KLOG_WARNING(LOG_TAG, "BatteryHealthPath not found\n");
        if (mHealthdConfig->batteryPresentPath.isEmpty())
            KLOG_WARNING(LOG_TAG, "BatteryPresentPath not found\n");
        if (mHealthdConfig->batteryCapacityPath.isEmpty())
            KLOG_WARNING(LOG_TAG, "BatteryCapacityPath not found\n");
        if (mHealthdConfig->batteryVoltagePath.isEmpty())
            KLOG_WARNING(LOG_TAG, "BatteryVoltagePath not found\n");
        if (mHealthdConfig->batteryTemperaturePath.isEmpty())
            KLOG_WARNING(LOG_TAG, "BatteryTemperaturePath not found\n");
        if (mHealthdConfig->batteryTechnologyPath.isEmpty())
            KLOG_WARNING(LOG_TAG, "BatteryTechnologyPath not found\n");
        if (mHealthdConfig->batteryCurrentNowPath.isEmpty())
            KLOG_WARNING(LOG_TAG, "BatteryCurrentNowPath not found\n");
        if (mHealthdConfig->batteryFullChargePath.isEmpty())
            KLOG_WARNING(LOG_TAG, "BatteryFullChargePath not found\n");
        if (mHealthdConfig->batteryCycleCountPath.isEmpty())
            KLOG_WARNING(LOG_TAG, "BatteryCycleCountPath not found\n");
        if (mHealthdConfig->batteryCapacityLevelPath.isEmpty())
            KLOG_WARNING(LOG_TAG, "batteryCapacityLevelPath not found\n");
        if (mHealthdConfig->batteryChargeTimeToFullNowPath.isEmpty())
            KLOG_WARNING(LOG_TAG, "batteryChargeTimeToFullNowPath. not found\n");
        if (mHealthdConfig->batteryFullChargeDesignCapacityUahPath.isEmpty())
            KLOG_WARNING(LOG_TAG, "batteryFullChargeDesignCapacityUahPath. not found\n");
    }

    if (property_get("ro.boot.fake_battery", pval, NULL) > 0
                                               && strtol(pval, NULL, 10) != 0) {
        mBatteryFixedCapacity = FAKE_BATTERY_CAPACITY;
        mBatteryFixedTemperature = FAKE_BATTERY_TEMPERATURE;
    }
}

}; // namespace android

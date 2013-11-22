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

#include "healthd.h"
#include "BatteryMonitor.h"
#include "BatteryPropertiesRegistrar.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <batteryservice/BatteryService.h>
#include <cutils/klog.h>
#include <utils/String8.h>
#include <utils/Vector.h>

#define POWER_SUPPLY_SUBSYSTEM "power_supply"
#define POWER_SUPPLY_SYSFS_PATH "/sys/class/" POWER_SUPPLY_SUBSYSTEM

namespace android {

struct sysfsStringEnumMap {
    char* s;
    int val;
};

static int mapSysfsString(const char* str,
                          struct sysfsStringEnumMap map[]) {
    for (int i = 0; map[i].s; i++)
        if (!strcmp(str, map[i].s))
            return map[i].val;

    return -1;
}

int BatteryMonitor::getBatteryStatus(const char* status) {
    int ret;
    struct sysfsStringEnumMap batteryStatusMap[] = {
        { "Unknown", BATTERY_STATUS_UNKNOWN },
        { "Charging", BATTERY_STATUS_CHARGING },
        { "Discharging", BATTERY_STATUS_DISCHARGING },
        { "Not charging", BATTERY_STATUS_NOT_CHARGING },
        { "Full", BATTERY_STATUS_FULL },
        { NULL, 0 },
    };

    ret = mapSysfsString(status, batteryStatusMap);
    if (ret < 0) {
        KLOG_WARNING(LOG_TAG, "Unknown battery status '%s'\n", status);
        ret = BATTERY_STATUS_UNKNOWN;
    }

    return ret;
}

int BatteryMonitor::getBatteryHealth(const char* status) {
    int ret;
    struct sysfsStringEnumMap batteryHealthMap[] = {
        { "Unknown", BATTERY_HEALTH_UNKNOWN },
        { "Good", BATTERY_HEALTH_GOOD },
        { "Overheat", BATTERY_HEALTH_OVERHEAT },
        { "Dead", BATTERY_HEALTH_DEAD },
        { "Over voltage", BATTERY_HEALTH_OVER_VOLTAGE },
        { "Unspecified failure", BATTERY_HEALTH_UNSPECIFIED_FAILURE },
        { "Cold", BATTERY_HEALTH_COLD },
        { NULL, 0 },
    };

    ret = mapSysfsString(status, batteryHealthMap);
    if (ret < 0) {
        KLOG_WARNING(LOG_TAG, "Unknown battery health '%s'\n", status);
        ret = BATTERY_HEALTH_UNKNOWN;
    }

    return ret;
}

int BatteryMonitor::readFromFile(const String8& path, char* buf, size_t size) {
    char *cp = NULL;

    if (path.isEmpty())
        return -1;
    int fd = open(path.string(), O_RDONLY, 0);
    if (fd == -1) {
        KLOG_ERROR(LOG_TAG, "Could not open '%s'\n", path.string());
        return -1;
    }

    ssize_t count = TEMP_FAILURE_RETRY(read(fd, buf, size));
    if (count > 0)
            cp = (char *)memrchr(buf, '\n', count);

    if (cp)
        *cp = '\0';
    else
        buf[0] = '\0';

    close(fd);
    return count;
}

BatteryMonitor::PowerSupplyType BatteryMonitor::readPowerSupplyType(const String8& path) {
    const int SIZE = 128;
    char buf[SIZE];
    int length = readFromFile(path, buf, SIZE);
    BatteryMonitor::PowerSupplyType ret;
    struct sysfsStringEnumMap supplyTypeMap[] = {
            { "Unknown", ANDROID_POWER_SUPPLY_TYPE_UNKNOWN },
            { "Battery", ANDROID_POWER_SUPPLY_TYPE_BATTERY },
            { "UPS", ANDROID_POWER_SUPPLY_TYPE_AC },
            { "Mains", ANDROID_POWER_SUPPLY_TYPE_AC },
            { "USB", ANDROID_POWER_SUPPLY_TYPE_USB },
            { "USB_DCP", ANDROID_POWER_SUPPLY_TYPE_AC },
            { "USB_CDP", ANDROID_POWER_SUPPLY_TYPE_AC },
            { "USB_ACA", ANDROID_POWER_SUPPLY_TYPE_AC },
            { "Wireless", ANDROID_POWER_SUPPLY_TYPE_WIRELESS },
            { NULL, 0 },
    };

    if (length <= 0)
        return ANDROID_POWER_SUPPLY_TYPE_UNKNOWN;

    ret = (BatteryMonitor::PowerSupplyType)mapSysfsString(buf, supplyTypeMap);
    if (ret < 0)
        ret = ANDROID_POWER_SUPPLY_TYPE_UNKNOWN;

    return ret;
}

bool BatteryMonitor::getBooleanField(const String8& path) {
    const int SIZE = 16;
    char buf[SIZE];

    bool value = false;
    if (readFromFile(path, buf, SIZE) > 0) {
        if (buf[0] != '0') {
            value = true;
        }
    }

    return value;
}

int BatteryMonitor::getIntField(const String8& path) {
    const int SIZE = 128;
    char buf[SIZE];

    int value = 0;
    if (readFromFile(path, buf, SIZE) > 0) {
        value = strtol(buf, NULL, 0);
    }
    return value;
}

bool BatteryMonitor::update(void) {
    struct BatteryProperties props;
    bool logthis;

    props.chargerAcOnline = false;
    props.chargerUsbOnline = false;
    props.chargerWirelessOnline = false;
    props.batteryStatus = BATTERY_STATUS_UNKNOWN;
    props.batteryHealth = BATTERY_HEALTH_UNKNOWN;
    props.batteryCurrentNow = INT_MIN;
    props.batteryChargeCounter = INT_MIN;

    if (!mHealthdConfig->batteryPresentPath.isEmpty())
        props.batteryPresent = getBooleanField(mHealthdConfig->batteryPresentPath);
    else
        props.batteryPresent = true;

    props.batteryLevel = getIntField(mHealthdConfig->batteryCapacityPath);
    props.batteryVoltage = getIntField(mHealthdConfig->batteryVoltagePath) / 1000;

    if (!mHealthdConfig->batteryCurrentNowPath.isEmpty())
        props.batteryCurrentNow = getIntField(mHealthdConfig->batteryCurrentNowPath);

    if (!mHealthdConfig->batteryChargeCounterPath.isEmpty())
        props.batteryChargeCounter = getIntField(mHealthdConfig->batteryChargeCounterPath);

    props.batteryTemperature = getIntField(mHealthdConfig->batteryTemperaturePath);

    const int SIZE = 128;
    char buf[SIZE];
    String8 btech;

    if (readFromFile(mHealthdConfig->batteryStatusPath, buf, SIZE) > 0)
        props.batteryStatus = getBatteryStatus(buf);

    if (readFromFile(mHealthdConfig->batteryHealthPath, buf, SIZE) > 0)
        props.batteryHealth = getBatteryHealth(buf);

    if (readFromFile(mHealthdConfig->batteryTechnologyPath, buf, SIZE) > 0)
        props.batteryTechnology = String8(buf);

    unsigned int i;

    for (i = 0; i < mChargerNames.size(); i++) {
        String8 path;
        path.appendFormat("%s/%s/online", POWER_SUPPLY_SYSFS_PATH,
                          mChargerNames[i].string());

        if (readFromFile(path, buf, SIZE) > 0) {
            if (buf[0] != '0') {
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
            }
        }
    }

    logthis = !healthd_board_battery_update(&props);

    if (logthis) {
        char dmesgline[256];
        snprintf(dmesgline, sizeof(dmesgline),
                 "battery l=%d v=%d t=%s%d.%d h=%d st=%d",
                 props.batteryLevel, props.batteryVoltage,
                 props.batteryTemperature < 0 ? "-" : "",
                 abs(props.batteryTemperature / 10),
                 abs(props.batteryTemperature % 10), props.batteryHealth,
                 props.batteryStatus);

        if (!mHealthdConfig->batteryCurrentNowPath.isEmpty()) {
            char b[20];

            snprintf(b, sizeof(b), " c=%d", props.batteryCurrentNow / 1000);
            strlcat(dmesgline, b, sizeof(dmesgline));
        }

        KLOG_INFO(LOG_TAG, "%s chg=%s%s%s\n", dmesgline,
                  props.chargerAcOnline ? "a" : "",
                  props.chargerUsbOnline ? "u" : "",
                  props.chargerWirelessOnline ? "w" : "");
    }

    if (mBatteryPropertiesRegistrar != NULL)
        mBatteryPropertiesRegistrar->notifyListeners(props);

    return props.chargerAcOnline | props.chargerUsbOnline |
            props.chargerWirelessOnline;
}

void BatteryMonitor::init(struct healthd_config *hc, bool nosvcmgr) {
    String8 path;

    mHealthdConfig = hc;
    DIR* dir = opendir(POWER_SUPPLY_SYSFS_PATH);
    if (dir == NULL) {
        KLOG_ERROR(LOG_TAG, "Could not open %s\n", POWER_SUPPLY_SYSFS_PATH);
    } else {
        struct dirent* entry;

        while ((entry = readdir(dir))) {
            const char* name = entry->d_name;

            if (!strcmp(name, ".") || !strcmp(name, ".."))
                continue;

            char buf[20];
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
                    } else {
                        path.clear();
                        path.appendFormat("%s/%s/batt_vol",
                                          POWER_SUPPLY_SYSFS_PATH, name);
                        if (access(path, R_OK) == 0)
                            mHealthdConfig->batteryVoltagePath = path;
                    }
                }

                if (mHealthdConfig->batteryCurrentNowPath.isEmpty()) {
                    path.clear();
                    path.appendFormat("%s/%s/current_now",
                                      POWER_SUPPLY_SYSFS_PATH, name);
                    if (access(path, R_OK) == 0)
                        mHealthdConfig->batteryCurrentNowPath = path;
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
                    } else {
                        path.clear();
                        path.appendFormat("%s/%s/batt_temp",
                                          POWER_SUPPLY_SYSFS_PATH, name);
                        if (access(path, R_OK) == 0)
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
        closedir(dir);
    }

    if (!mChargerNames.size())
        KLOG_ERROR(LOG_TAG, "No charger supplies found\n");
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

    if (nosvcmgr == false) {
            mBatteryPropertiesRegistrar = new BatteryPropertiesRegistrar(this);
            mBatteryPropertiesRegistrar->publish();
    }
}

}; // namespace android

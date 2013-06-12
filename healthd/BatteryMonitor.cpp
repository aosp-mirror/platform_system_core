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

    props.chargerAcOnline = false;
    props.chargerUsbOnline = false;
    props.chargerWirelessOnline = false;
    props.batteryStatus = BATTERY_STATUS_UNKNOWN;
    props.batteryHealth = BATTERY_HEALTH_UNKNOWN;

    if (!mBatteryPresentPath.isEmpty())
        props.batteryPresent = getBooleanField(mBatteryPresentPath);
    else
        props.batteryPresent = true;

    props.batteryLevel = getIntField(mBatteryCapacityPath);
    props.batteryVoltage = getIntField(mBatteryVoltagePath) / 1000;
    props.batteryTemperature = getIntField(mBatteryTemperaturePath);

    const int SIZE = 128;
    char buf[SIZE];
    String8 btech;

    if (readFromFile(mBatteryStatusPath, buf, SIZE) > 0)
        props.batteryStatus = getBatteryStatus(buf);

    if (readFromFile(mBatteryHealthPath, buf, SIZE) > 0)
        props.batteryHealth = getBatteryHealth(buf);

    if (readFromFile(mBatteryTechnologyPath, buf, SIZE) > 0)
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

    KLOG_INFO(LOG_TAG, "battery l=%d v=%d t=%s%d.%d h=%d st=%d chg=%s%s%s\n",
              props.batteryLevel, props.batteryVoltage,
              props.batteryTemperature < 0 ? "-" : "",
              abs(props.batteryTemperature / 10),
              abs(props.batteryTemperature % 10), props.batteryHealth,
              props.batteryStatus,
              props.chargerAcOnline ? "a" : "",
              props.chargerUsbOnline ? "u" : "",
              props.chargerWirelessOnline ? "w" : "");

    if (mBatteryPropertiesRegistrar != NULL)
        mBatteryPropertiesRegistrar->notifyListeners(props);

    return props.chargerAcOnline | props.chargerUsbOnline |
            props.chargerWirelessOnline;
}

void BatteryMonitor::init(bool nosvcmgr) {
    String8 path;

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
                path.clear();
                path.appendFormat("%s/%s/status", POWER_SUPPLY_SYSFS_PATH, name);
                if (access(path, R_OK) == 0)
                    mBatteryStatusPath = path;
                path.clear();
                path.appendFormat("%s/%s/health", POWER_SUPPLY_SYSFS_PATH, name);
                if (access(path, R_OK) == 0)
                    mBatteryHealthPath = path;
                path.clear();
                path.appendFormat("%s/%s/present", POWER_SUPPLY_SYSFS_PATH, name);
                if (access(path, R_OK) == 0)
                    mBatteryPresentPath = path;
                path.clear();
                path.appendFormat("%s/%s/capacity", POWER_SUPPLY_SYSFS_PATH, name);
                if (access(path, R_OK) == 0)
                    mBatteryCapacityPath = path;

                path.clear();
                path.appendFormat("%s/%s/voltage_now", POWER_SUPPLY_SYSFS_PATH, name);
                if (access(path, R_OK) == 0) {
                    mBatteryVoltagePath = path;
                } else {
                    path.clear();
                    path.appendFormat("%s/%s/batt_vol", POWER_SUPPLY_SYSFS_PATH, name);
                    if (access(path, R_OK) == 0)
                            mBatteryVoltagePath = path;
                }

                path.clear();
                path.appendFormat("%s/%s/temp", POWER_SUPPLY_SYSFS_PATH, name);
                if (access(path, R_OK) == 0) {
                    mBatteryTemperaturePath = path;
                } else {
                    path.clear();
                    path.appendFormat("%s/%s/batt_temp", POWER_SUPPLY_SYSFS_PATH, name);
                    if (access(path, R_OK) == 0)
                            mBatteryTemperaturePath = path;
                }

                path.clear();
                path.appendFormat("%s/%s/technology", POWER_SUPPLY_SYSFS_PATH, name);
                if (access(path, R_OK) == 0)
                    mBatteryTechnologyPath = path;
                break;

            case ANDROID_POWER_SUPPLY_TYPE_UNKNOWN:
                break;
            }
        }
        closedir(dir);
    }

    if (!mChargerNames.size())
        KLOG_ERROR(LOG_TAG, "No charger supplies found\n");
    if (mBatteryStatusPath.isEmpty())
        KLOG_WARNING(LOG_TAG, "BatteryStatusPath not found\n");
    if (mBatteryHealthPath.isEmpty())
        KLOG_WARNING("BatteryHealthPath not found\n");
    if (mBatteryPresentPath.isEmpty())
        KLOG_WARNING(LOG_TAG, "BatteryPresentPath not found\n");
    if (mBatteryCapacityPath.isEmpty())
        KLOG_WARNING(LOG_TAG, "BatteryCapacityPath not found\n");
    if (mBatteryVoltagePath.isEmpty())
        KLOG_WARNING(LOG_TAG, "BatteryVoltagePath not found\n");
    if (mBatteryTemperaturePath.isEmpty())
        KLOG_WARNING(LOG_TAG, "BatteryTemperaturePath not found\n");
    if (mBatteryTechnologyPath.isEmpty())
        KLOG_WARNING(LOG_TAG, "BatteryTechnologyPath not found\n");

    if (nosvcmgr == false) {
            mBatteryPropertiesRegistrar = new BatteryPropertiesRegistrar(this);
            mBatteryPropertiesRegistrar->publish();
    }
}

}; // namespace android

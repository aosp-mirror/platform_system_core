/*
 * Copyright (C) 2009-2016 The Android Open Source Project
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

#define LOG_TAG "Service"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/system_properties.h>
#include <unistd.h>

#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <log/log.h>
#include <sysutils/ServiceManager.h>

ServiceManager::ServiceManager() {
}

// The length of a service name should not exceed SERVICE_NAME_MAX. Starting
// a service is done by writing its name to the "ctl.start" system property
// and stopping a service is done by writing its name to "ctl.stop". If a
// service name is too long to fit in a property, you won't be able to start
// or stop it.
static constexpr size_t SERVICE_NAME_MAX = PROP_VALUE_MAX;

/* The maximum amount of time to wait for a service to start or stop,
 * in micro-seconds (really an approximation) */
#define  SLEEP_MAX_USEC     2000000  /* 2 seconds */

/* The minimal sleeping interval between checking for the service's state
 * when looping for SLEEP_MAX_USEC */
#define  SLEEP_MIN_USEC      200000  /* 200 msec */

int ServiceManager::start(const char *name) {
    if (strlen(name) > SERVICE_NAME_MAX) {
        SLOGE("Service name '%s' is too long", name);
        return 0;
    }

    if (isRunning(name)) {
        SLOGW("Service '%s' is already running", name);
        return 0;
    }

    SLOGD("Starting service '%s'", name);
    android::base::SetProperty("ctl.start", name);

    int count = SLEEP_MAX_USEC;
    while(count > 0) {
        usleep(SLEEP_MIN_USEC);
        count -= SLEEP_MIN_USEC;
        if (isRunning(name))
            break;
    }
    if (count <= 0) {
        SLOGW("Timed out waiting for service '%s' to start", name);
        errno = ETIMEDOUT;
        return -1;
    }
    SLOGD("Sucessfully started '%s'", name);
    return 0;
}

int ServiceManager::stop(const char *name) {
    if (strlen(name) > SERVICE_NAME_MAX) {
        SLOGE("Service name '%s' is too long", name);
        return 0;
    }

    if (!isRunning(name)) {
        SLOGW("Service '%s' is already stopped", name);
        return 0;
    }

    SLOGD("Stopping service '%s'", name);
    android::base::SetProperty("ctl.stop", name);

    int count = SLEEP_MAX_USEC;
    while(count > 0) {
        usleep(SLEEP_MIN_USEC);
        count -= SLEEP_MIN_USEC;
        if (!isRunning(name))
            break;
    }

    if (count <= 0) {
        SLOGW("Timed out waiting for service '%s' to stop", name);
        errno = ETIMEDOUT;
        return -1;
    }
    SLOGD("Successfully stopped '%s'", name);
    return 0;
}

bool ServiceManager::isRunning(const char *name) {
    std::string property_name = android::base::StringPrintf("init.svc.%s", name);
    return (android::base::GetProperty(property_name, "") == "running");
}

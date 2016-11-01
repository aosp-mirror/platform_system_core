/*
 * Copyright (C) 2016 The Android Open Source Project
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
#define KLOG_LEVEL 6

#include <healthd/healthd.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <cutils/klog.h>

using namespace android;

// main healthd loop
extern int healthd_main(void);

// Android mode

extern void healthd_mode_android_init(struct healthd_config *config);
extern int healthd_mode_android_preparetowait(void);
extern void healthd_mode_android_heartbeat(void);
extern void healthd_mode_android_battery_update(
    struct android::BatteryProperties *props);

static struct healthd_mode_ops android_ops = {
    .init = healthd_mode_android_init,
    .preparetowait = healthd_mode_android_preparetowait,
    .heartbeat = healthd_mode_android_heartbeat,
    .battery_update = healthd_mode_android_battery_update,
};

int main(int /*argc*/, char ** /*argv*/) {

    healthd_mode_ops = &android_ops;

    return healthd_main();
}

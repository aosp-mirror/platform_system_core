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

#define LOG_TAG "charger"
#define KLOG_LEVEL 6

#include <health2/Health.h>
#include <healthd/healthd.h>

#include <stdlib.h>
#include <string.h>
#include <cutils/klog.h>

using namespace android;

// main healthd loop
extern int healthd_main(void);

// Charger mode

extern void healthd_mode_charger_init(struct healthd_config *config);
extern int healthd_mode_charger_preparetowait(void);
extern void healthd_mode_charger_heartbeat(void);
extern void healthd_mode_charger_battery_update(
    struct android::BatteryProperties *props);

// NOPs for modes that need no special action

static void healthd_mode_nop_init(struct healthd_config *config);
static int healthd_mode_nop_preparetowait(void);
static void healthd_mode_nop_heartbeat(void);
static void healthd_mode_nop_battery_update(
    struct android::BatteryProperties *props);

static struct healthd_mode_ops healthd_nops = {
    .init = healthd_mode_nop_init,
    .preparetowait = healthd_mode_nop_preparetowait,
    .heartbeat = healthd_mode_nop_heartbeat,
    .battery_update = healthd_mode_nop_battery_update,
};

#ifdef CHARGER_NO_UI
static struct healthd_mode_ops charger_ops = healthd_nops;
#else
static struct healthd_mode_ops charger_ops = {
    .init = healthd_mode_charger_init,
    .preparetowait = healthd_mode_charger_preparetowait,
    .heartbeat = healthd_mode_charger_heartbeat,
    .battery_update = healthd_mode_charger_battery_update,
};
#endif

static void healthd_mode_nop_init(struct healthd_config* config) {
    using android::hardware::health::V2_0::implementation::Health;
    Health::initInstance(config);
}

static int healthd_mode_nop_preparetowait(void) {
    return -1;
}

static void healthd_mode_nop_heartbeat(void) {
}

static void healthd_mode_nop_battery_update(
    struct android::BatteryProperties* /*props*/) {
}

int healthd_charger_main(int argc, char** argv) {
    int ch;

    healthd_mode_ops = &charger_ops;

    while ((ch = getopt(argc, argv, "cr")) != -1) {
        switch (ch) {
            case 'c':
                // -c is now a noop
                break;
            case 'r':
                // force nops for recovery
                healthd_mode_ops = &healthd_nops;
                break;
            case '?':
            default:
                KLOG_ERROR(LOG_TAG, "Unrecognized charger option: %c\n",
                        optopt);
                exit(1);
        }
    }

    return healthd_main();
}

#ifndef CHARGER_TEST
int main(int argc, char** argv) {
    return healthd_charger_main(argc, argv);
}
#endif

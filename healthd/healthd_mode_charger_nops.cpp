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

#include "healthd_mode_charger_nops.h"

#include <health2/Health.h>
#include <healthd/healthd.h>

#include <stdlib.h>
#include <string.h>

using namespace android;

// main healthd loop
extern int healthd_main(void);

// NOPs for modes that need no special action

static void healthd_mode_nop_init(struct healthd_config* config);
static int healthd_mode_nop_preparetowait(void);
static void healthd_mode_nop_heartbeat(void);
static void healthd_mode_nop_battery_update(struct android::BatteryProperties* props);

static struct healthd_mode_ops healthd_nops = {
        .init = healthd_mode_nop_init,
        .preparetowait = healthd_mode_nop_preparetowait,
        .heartbeat = healthd_mode_nop_heartbeat,
        .battery_update = healthd_mode_nop_battery_update,
};

static void healthd_mode_nop_init(struct healthd_config* config) {
    using android::hardware::health::V2_0::implementation::Health;
    Health::initInstance(config);
}

static int healthd_mode_nop_preparetowait(void) {
    return -1;
}

static void healthd_mode_nop_heartbeat(void) {}

static void healthd_mode_nop_battery_update(struct android::BatteryProperties* /*props*/) {}

int healthd_charger_nops(int /* argc */, char** /* argv */) {
    healthd_mode_ops = &healthd_nops;
    return healthd_main();
}

/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include <health2/service.h>
#include <healthd/healthd.h>

void healthd_board_init(struct healthd_config*) {
    // Implementation-defined init logic goes here.
    // 1. config->periodic_chores_interval_* variables
    // 2. config->battery*Path variables
    // 3. config->energyCounter. In this implementation, energyCounter is not defined.

    // use defaults
}

int healthd_board_battery_update(struct android::BatteryProperties*) {
    // Implementation-defined update logic goes here. An implementation
    // can make modifications to prop before broadcasting it to all callbacks.

    // return 0 to log periodic polled battery status to kernel log
    return 0;
}

int main() {
    return health_service_main();
}

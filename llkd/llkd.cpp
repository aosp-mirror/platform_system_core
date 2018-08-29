/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include "llkd.h"

#include <sched.h>
#include <sys/prctl.h>
#include <unistd.h>

#include <chrono>

#include <android-base/logging.h>

using namespace std::chrono;

int main(int, char**) {
    prctl(PR_SET_DUMPABLE, 0);

    LOG(INFO) << "started";

    bool enabled = llkInit();

    // Would like this policy to be automatic as part of libllkd,
    // but that would be presumptuous and bad side-effect.
    struct sched_param param;
    memset(&param, 0, sizeof(param));
    sched_setscheduler(0, SCHED_BATCH, &param);

    while (true) {
        if (enabled) {
            ::usleep(duration_cast<microseconds>(llkCheck()).count());
        } else {
            ::pause();
        }
    }
    // NOTREACHED

    LOG(INFO) << "exiting";
    return 0;
}

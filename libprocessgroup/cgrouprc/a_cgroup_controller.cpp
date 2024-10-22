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

#include <android-base/logging.h>
#include <android/cgrouprc.h>

#include "cgrouprc_internal.h"

// All ACgroupController_* functions implicitly convert the pointer back
// to the original CgroupController pointer before invoking the member functions.

uint32_t ACgroupController_getVersion(const ACgroupController* controller) {
    CHECK(controller != nullptr);
    return controller->version();
}

uint32_t ACgroupController_getFlags(const ACgroupController* controller) {
    CHECK(controller != nullptr);
    return controller->flags();
}

const char* ACgroupController_getName(const ACgroupController* controller) {
    CHECK(controller != nullptr);
    return controller->name();
}

const char* ACgroupController_getPath(const ACgroupController* controller) {
    CHECK(controller != nullptr);
    return controller->path();
}

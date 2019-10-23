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

#pragma once

#include <sys/types.h>

#include <string>

namespace android {
namespace init {

static const int MIN_OOM_SCORE_ADJUST = -1000;
static const int MAX_OOM_SCORE_ADJUST = 1000;
// service with default score is unkillable
static const int DEFAULT_OOM_SCORE_ADJUST = MIN_OOM_SCORE_ADJUST;

#if defined(__ANDROID__)

void LmkdRegister(const std::string& name, uid_t uid, pid_t pid, int oom_score_adjust);
void LmkdUnregister(const std::string& name, pid_t pid);

#else  // defined(__ANDROID__)

static inline void LmkdRegister(const std::string&, uid_t, pid_t, int) {}
static inline void LmkdUnregister(const std::string&, pid_t) {}

#endif  // defined(__ANDROID__)

}  // namespace init
}  // namespace android

/*
 * Copyright (C) 2024 The Android Open Source Project
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

// Note that parser will perform arity checks only.

#include <android-base/result.h>

#include "builtin_arguments.h"
#include "builtins.h"

namespace android::init {

static base::Result<void> check_stub(const BuiltinArguments&) {
    return {};
}

#include "noop_builtin_function_map.h"

}  // namespace android::init

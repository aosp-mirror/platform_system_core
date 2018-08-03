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

#pragma once

#include "adb_unique_fd.h"

enum class SubprocessType {
    kPty,
    kRaw,
};

enum class SubprocessProtocol {
    kNone,
    kShell,
};

// Forks and starts a new shell subprocess. If |name| is empty an interactive
// shell is started, otherwise |name| is executed non-interactively.
//
// Returns an open FD connected to the subprocess or -1 on failure.
unique_fd StartSubprocess(const char* name, const char* terminal_type, SubprocessType type,
                          SubprocessProtocol protocol);

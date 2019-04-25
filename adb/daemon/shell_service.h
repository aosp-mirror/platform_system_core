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

#include <string>

#include "adb_unique_fd.h"

#include <string_view>

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
unique_fd StartSubprocess(std::string name, const char* terminal_type, SubprocessType type,
                          SubprocessProtocol protocol);

// The same as above but with more fined grained control and custom error handling.
unique_fd StartSubprocess(std::string name, const char* terminal_type, SubprocessType type,
                          SubprocessProtocol protocol, bool make_pty_raw,
                          SubprocessProtocol error_protocol, unique_fd* error_fd);

// Executes |command| in a separate thread.
// Sets up in/out and error streams to emulate shell-like behavior.
//
// Returns an open FD connected to the thread or -1 on failure.
using Command = int(std::string_view args, int in, int out, int err);
unique_fd StartCommandInProcess(std::string name, Command command, SubprocessProtocol protocol);

// Create a pipe containing the error.
unique_fd ReportError(SubprocessProtocol protocol, const std::string& message);

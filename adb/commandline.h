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

#ifndef COMMANDLINE_H
#define COMMANDLINE_H

#include "adb.h"

int adb_commandline(int argc, const char** argv);
int usage();

// Connects to the device "shell" service with |command| and prints the
// resulting output.
int send_shell_command(TransportType transport_type, const char* serial, const std::string& command,
                       bool disable_shell_protocol, std::string* output = nullptr,
                       std::string* err = nullptr);

#endif  // COMMANDLINE_H

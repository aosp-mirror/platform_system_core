/*
 * Copyright (C) 2015 The Android Open Source Project
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

#ifndef _ADB_CLIENT_H_
#define _ADB_CLIENT_H_

#include "adb.h"

#include <string>

// Connect to adb, connect to the named service, and return a valid fd for
// interacting with that service upon success or a negative number on failure.
int adb_connect(const std::string& service, std::string* error);
int _adb_connect(const std::string& service, std::string* error);

// Connect to adb, connect to the named service, returns true if the connection
// succeeded AND the service returned OKAY. Outputs any returned error otherwise.
bool adb_command(const std::string& service);

// Connects to the named adb service and fills 'result' with the response.
// Returns true on success; returns false and fills 'error' on failure.
bool adb_query(const std::string& service, std::string* result, std::string* error);

// Set the preferred transport to connect to.
void adb_set_transport(TransportType type, const char* serial);

// Set TCP specifics of the transport to use.
void adb_set_tcp_specifics(int server_port);

// Set TCP Hostname of the transport to use.
void adb_set_tcp_name(const char* hostname);

// Send commands to the current emulator instance. Will fail if there is not
// exactly one emulator connected (or if you use -s <serial> with a <serial>
// that does not designate an emulator).
int adb_send_emulator_command(int argc, const char** argv, const char* serial);

// Reads a standard adb status response (OKAY|FAIL) and returns true in the
// event of OKAY, false in the event of FAIL or protocol error.
bool adb_status(int fd, std::string* error);

#endif

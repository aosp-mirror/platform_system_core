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

#pragma once

#include "adb.h"
#include "sysdeps.h"
#include "transport.h"

#include <optional>
#include <string>

// Explicitly check the adb server version.
// All of the commands below do this implicitly.
// Only the first invocation of this function will check the server version.
bool adb_check_server_version(std::string* _Nonnull error);

// Connect to adb, connect to the named service, and return a valid fd for
// interacting with that service upon success or a negative number on failure.
int adb_connect(std::string_view service, std::string* _Nonnull error);

// Same as above, except returning the TransportId for the service that we've connected to.
int adb_connect(TransportId* _Nullable id, std::string_view service, std::string* _Nonnull error);

// Kill the currently running adb server, if it exists.
bool adb_kill_server();

// Connect to adb, connect to the named service, returns true if the connection
// succeeded AND the service returned OKAY. Outputs any returned error otherwise.
bool adb_command(const std::string& service);

// Connects to the named adb service and fills 'result' with the response.
// Returns true on success; returns false and fills 'error' on failure.
bool adb_query(const std::string& service, std::string* _Nonnull result,
               std::string* _Nonnull error);

// Set the preferred transport to connect to.
void adb_set_transport(TransportType type, const char* _Nullable serial, TransportId transport_id);
void adb_get_transport(TransportType* _Nullable type, const char* _Nullable* _Nullable serial,
                       TransportId* _Nullable transport_id);

// Set the socket specification for the adb server.
// This function can only be called once, and the argument must live to the end of the process.
void adb_set_socket_spec(const char* _Nonnull socket_spec);

// Send commands to the current emulator instance. Will fail if there is not
// exactly one emulator connected (or if you use -s <serial> with a <serial>
// that does not designate an emulator).
int adb_send_emulator_command(int argc, const char* _Nonnull* _Nonnull argv,
                              const char* _Nullable serial);

// Reads a standard adb status response (OKAY|FAIL) and returns true in the
// event of OKAY, false in the event of FAIL or protocol error.
bool adb_status(int fd, std::string* _Nonnull error);

// Create a host command corresponding to selected transport type/serial.
std::string format_host_command(const char* _Nonnull command);

// Get the feature set of the current preferred transport.
bool adb_get_feature_set(FeatureSet* _Nonnull feature_set, std::string* _Nonnull error);

#if defined(__linux__)
// Get the path of a file containing the path to the server executable, if the socket spec set via
// adb_set_socket_spec is a local one.
std::optional<std::string> adb_get_server_executable_path();
#endif

// Globally acccesible argv/envp, for the purpose of re-execing adb.
extern const char* _Nullable * _Nullable __adb_argv;
extern const char* _Nullable * _Nullable __adb_envp;

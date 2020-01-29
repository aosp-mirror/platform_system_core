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

#include <stdint.h>
#include <sys/types.h>

#include <android-base/unique_fd.h>

extern "C" {

struct AdbConnectionClientContext;

enum AdbConnectionClientInfoType {
  pid,
  debuggable,
};

struct AdbConnectionClientInfo {
  AdbConnectionClientInfoType type;
  union {
    uint64_t pid;
    bool debuggable;
  } data;
};

// Construct a context and connect to adbd.
// Returns null if we fail to connect to adbd.
AdbConnectionClientContext* adbconnection_client_new(
    const AdbConnectionClientInfo* const* info_elems, size_t info_count);

void adbconnection_client_destroy(AdbConnectionClientContext* ctx);

// Get an fd which can be polled upon to detect when a jdwp socket is available.
// You do not own this fd. Do not close it.
int adbconnection_client_pollfd(AdbConnectionClientContext* ctx);

// Receive a jdwp client fd.
// Ownership is transferred to the caller of this function.
int adbconnection_client_receive_jdwp_fd(AdbConnectionClientContext* ctx);
}

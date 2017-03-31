/*
 * Copyright 2016, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <stdint.h>

// Sockets in the ANDROID_SOCKET_NAMESPACE_RESERVED namespace.
// Both sockets are SOCK_SEQPACKET sockets, so no explicit length field is needed.
constexpr char kTombstonedCrashSocketName[] = "tombstoned_crash";
constexpr char kTombstonedInterceptSocketName[] = "tombstoned_intercept";

enum class CrashPacketType : uint8_t {
  // Initial request from crash_dump.
  kDumpRequest = 0,

  // Notification of a completed crash dump.
  // Sent after a dump is completed and the process has been untraced, but
  // before it has been resumed with SIGCONT.
  kCompletedDump,

  // Responses to kRequest.
  // kPerformDump sends along an output fd via cmsg(3).
  kPerformDump = 128,
  kAbortDump,
};

struct DumpRequest {
  int32_t pid;
};

// The full packet must always be written, regardless of whether the union is used.
struct TombstonedCrashPacket {
  CrashPacketType packet_type;
  union {
    DumpRequest dump_request;
  } packet;
};

// Comes with a file descriptor via SCM_RIGHTS.
// This packet should be sent before an actual dump happens.
struct InterceptRequest {
  int32_t pid;
};

enum class InterceptStatus : uint8_t {
  kFailed,
  kStarted,
  kRegistered,
};

// Sent either immediately upon failure, or when the intercept has been used.
struct InterceptResponse {
  InterceptStatus status;
  char error_message[127];  // always null-terminated
};

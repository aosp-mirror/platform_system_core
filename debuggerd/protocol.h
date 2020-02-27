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

#include <signal.h>
#include <stdint.h>
#include <sys/ucontext.h>
#include <unistd.h>

#include "dump_type.h"

// Sockets in the ANDROID_SOCKET_NAMESPACE_RESERVED namespace.
// Both sockets are SOCK_SEQPACKET sockets, so no explicit length field is needed.
constexpr char kTombstonedCrashSocketName[] = "tombstoned_crash";
constexpr char kTombstonedJavaTraceSocketName[] = "tombstoned_java_trace";
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
  DebuggerdDumpType dump_type;
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
  DebuggerdDumpType dump_type;
  int32_t pid;
};

enum class InterceptStatus : uint8_t {
  // Returned when an intercept of a different type has already been
  // registered (and is active) for a given PID.
  kFailedAlreadyRegistered,
  // Returned in all other failure cases.
  kFailed,
  kStarted,
  kRegistered,
};

// Sent either immediately upon failure, or when the intercept has been used.
struct InterceptResponse {
  InterceptStatus status;
  char error_message[127];  // always null-terminated
};

// Sent from handler to crash_dump via pipe.
struct __attribute__((__packed__)) CrashInfoHeader {
  uint32_t version;
};

struct __attribute__((__packed__)) CrashInfoDataV1 {
  siginfo_t siginfo;
  ucontext_t ucontext;
  uintptr_t abort_msg_address;
};

struct __attribute__((__packed__)) CrashInfoDataV2 : public CrashInfoDataV1 {
  uintptr_t fdsan_table_address;
};

struct __attribute__((__packed__)) CrashInfoDataV3 : public CrashInfoDataV2 {
  uintptr_t gwp_asan_state;
  uintptr_t gwp_asan_metadata;
};

struct __attribute__((__packed__)) CrashInfo {
  CrashInfoHeader header;
  union {
    CrashInfoDataV1 v1;
    CrashInfoDataV2 v2;
    CrashInfoDataV3 v3;
  } data;
};

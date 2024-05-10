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

#include <sys/types.h>

#include <unordered_map>

#include <event2/event.h>
#include <event2/listener.h>

#include <android-base/unique_fd.h>

#include "dump_type.h"

struct InterceptManager;
struct InterceptRequest;
struct InterceptResponse;

struct Intercept {
  ~Intercept();

  InterceptManager* intercept_manager = nullptr;
  event* intercept_event = nullptr;
  android::base::unique_fd sockfd;

  pid_t pid = -1;
  android::base::unique_fd output_fd;
  bool registered = false;
  DebuggerdDumpType dump_type = kDebuggerdNativeBacktrace;
};

struct InterceptManager {
  event_base* base;
  std::unordered_map<pid_t, std::unordered_map<DebuggerdDumpType, Intercept*>> intercepts;
  evconnlistener* listener = nullptr;

  InterceptManager(event_base* _Nonnull base, int intercept_socket);
  InterceptManager(InterceptManager& copy) = delete;
  InterceptManager(InterceptManager&& move) = delete;

  bool CanRegister(const InterceptRequest& request, InterceptResponse& response);
  Intercept* Get(const pid_t pid, const DebuggerdDumpType dump_type);
  void Register(Intercept* intercept);
  void Unregister(Intercept* intercept);

  bool FindIntercept(pid_t pid, DebuggerdDumpType dump_type, android::base::unique_fd* out_fd);
};

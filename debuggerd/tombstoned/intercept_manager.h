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

struct Intercept {
  ~Intercept() {
    event_free(intercept_event);
  }

  InterceptManager* intercept_manager = nullptr;
  event* intercept_event = nullptr;
  android::base::unique_fd sockfd;

  pid_t intercept_pid = -1;
  android::base::unique_fd output_fd;
  bool registered = false;
  DebuggerdDumpType dump_type = kDebuggerdNativeBacktrace;
};

struct InterceptManager {
  event_base* base;
  std::unordered_map<pid_t, std::unique_ptr<Intercept>> intercepts;
  evconnlistener* listener = nullptr;

  InterceptManager(event_base* _Nonnull base, int intercept_socket);
  InterceptManager(InterceptManager& copy) = delete;
  InterceptManager(InterceptManager&& move) = delete;

  bool GetIntercept(pid_t pid, DebuggerdDumpType dump_type, android::base::unique_fd* out_fd);
};

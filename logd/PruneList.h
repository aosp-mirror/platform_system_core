/*
 * Copyright (C) 2014 The Android Open Source Project
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

#include <sys/types.h>

#include <string.h>
#include <list>

#include "LogBufferElement.h"

class Prune {
  public:
    static const uid_t UID_ALL = (uid_t)-1;
    static const pid_t PID_ALL = (pid_t)-1;

    Prune(uid_t uid, pid_t pid) : uid_(uid), pid_(pid) {}

    bool Matches(LogBufferElement* element) const;
    std::string Format() const;

    uid_t uid() const { return uid_; }
    pid_t pid() const { return pid_; }

  private:
    const uid_t uid_;
    const pid_t pid_;
};

class PruneList {
  public:
    PruneList();

    bool Init(const char* str);
    std::string Format() const;

    bool IsHighPriority(LogBufferElement* element) const;
    bool IsLowPriority(LogBufferElement* element) const;

    bool HasHighPriorityPruneRules() const { return !high_priority_prune_.empty(); }
    bool HasLowPriorityPruneRules() const { return !low_priority_prune_.empty(); }

    bool worst_uid_enabled() const { return worst_uid_enabled_; }
    bool worst_pid_of_system_enabled() const { return worst_pid_of_system_enabled_; }

  private:
    std::list<Prune> high_priority_prune_;
    std::list<Prune> low_priority_prune_;

    bool worst_uid_enabled_;
    bool worst_pid_of_system_enabled_;
};

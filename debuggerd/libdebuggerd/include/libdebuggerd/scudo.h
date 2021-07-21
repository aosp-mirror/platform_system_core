/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include "types.h"
#include "utility.h"

#include <memory.h>

#include "scudo/interface.h"

class Cause;
class Tombstone;

class ScudoCrashData {
 public:
  ScudoCrashData() = delete;
  ~ScudoCrashData() = default;
  ScudoCrashData(unwindstack::Memory* process_memory, const ProcessInfo& process_info);

  bool CrashIsMine() const;

  void DumpCause(log_t* log, unwindstack::Unwinder* unwinder) const;
  void AddCauseProtos(Tombstone* tombstone, unwindstack::Unwinder* unwinder) const;

 private:
  scudo_error_info error_info_ = {};
  uintptr_t untagged_fault_addr_;

  void DumpReport(const scudo_error_report* report, log_t* log,
                  unwindstack::Unwinder* unwinder) const;

  void FillInCause(Cause* cause, const scudo_error_report* report,
                   unwindstack::Unwinder* unwinder) const;
};

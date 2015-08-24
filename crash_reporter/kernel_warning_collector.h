/*
 * Copyright (C) 2013 The Android Open Source Project
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

#ifndef CRASH_REPORTER_KERNEL_WARNING_COLLECTOR_H_
#define CRASH_REPORTER_KERNEL_WARNING_COLLECTOR_H_

#include <string>

#include <base/macros.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST

#include "crash_collector.h"

// Kernel warning collector.
class KernelWarningCollector : public CrashCollector {
 public:
  KernelWarningCollector();

  ~KernelWarningCollector() override;

  // Collects warning.
  bool Collect();

 private:
  friend class KernelWarningCollectorTest;
  FRIEND_TEST(KernelWarningCollectorTest, CollectOK);

  // Reads the full content of the kernel warn dump and its signature.
  bool LoadKernelWarning(std::string *content, std::string *signature);

  DISALLOW_COPY_AND_ASSIGN(KernelWarningCollector);
};

#endif  // CRASH_REPORTER_KERNEL_WARNING_COLLECTOR_H_

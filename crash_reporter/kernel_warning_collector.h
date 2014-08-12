// Copyright (c) 2013 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRASH_REPORTER_KERNEL_WARNING_COLLECTOR_H_
#define CRASH_REPORTER_KERNEL_WARNING_COLLECTOR_H_

#include <string>

#include <gtest/gtest_prod.h>  // for FRIEND_TEST

#include "crash-reporter/crash_collector.h"

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
};

#endif  // CRASH_REPORTER_KERNEL_WARNING_COLLECTOR_H_

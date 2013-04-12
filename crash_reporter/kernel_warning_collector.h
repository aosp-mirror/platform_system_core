// Copyright (c) 2013 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef _CRASH_REPORTER_KERNEL_WARNING_COLLECTOR_H_
#define _CRASH_REPORTER_KERNEL_WARNING_COLLECTOR_H_

#include <gtest/gtest_prod.h>  // for FRIEND_TEST
#include <string>

#include "crash-reporter/crash_collector.h"

// Kernel warning collector.
class KernelWarningCollector : public CrashCollector {
 public:
  KernelWarningCollector();

  virtual ~KernelWarningCollector();

  // Collects warning.
  bool Collect();

 private:
  friend class KernelWarningCollectorTest;
  FRIEND_TEST(KernelWarningCollectorTest, CollectOK);

  // Reads the full content of the kernel warn dump and the warning hash.
  bool LoadKernelWarning(std::string *hash, std::string *content);
};

#endif  // _CRASH_REPORTER_KERNEL_WARNING_COLLECTOR_H_

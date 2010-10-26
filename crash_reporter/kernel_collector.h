// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef _CRASH_REPORTER_KERNEL_COLLECTOR_H_
#define _CRASH_REPORTER_KERNEL_COLLECTOR_H_

#include <pcrecpp.h>

#include <string>

#include "base/file_path.h"
#include "crash-reporter/crash_collector.h"
#include "gtest/gtest_prod.h"  // for FRIEND_TEST

class FilePath;

// Kernel crash collector.
class KernelCollector : public CrashCollector {
 public:
  KernelCollector();

  virtual ~KernelCollector();

  void OverridePreservedDumpPath(const FilePath &file_path);

  // Enable collection.
  bool Enable();

  // Returns true if the kernel collection currently enabled.
  bool IsEnabled() {
    return is_enabled_;
  }

  // Collect any preserved kernel crash dump. Returns true if there was
  // a dump (even if there were problems storing the dump), false otherwise.
  bool Collect();

  // Compute a stack signature string from a kernel dump.
  bool ComputeKernelStackSignature(const std::string &kernel_dump,
                                   std::string *kernel_signature,
                                   bool print_diagnostics);

 private:
  friend class KernelCollectorTest;
  FRIEND_TEST(KernelCollectorTest, ClearPreservedDump);
  FRIEND_TEST(KernelCollectorTest, LoadPreservedDump);
  FRIEND_TEST(KernelCollectorTest, CollectOK);

  bool LoadPreservedDump(std::string *contents);
  bool ClearPreservedDump();

  void ProcessStackTrace(pcrecpp::StringPiece kernel_dump,
                         bool print_diagnostics,
                         unsigned *hash,
                         float *last_stack_timestamp);
  bool FindCrashingFunction(pcrecpp::StringPiece kernel_dump,
                            bool print_diagnostics,
                            float stack_trace_timestamp,
                            std::string *crashing_function);
  bool FindPanicMessage(pcrecpp::StringPiece kernel_dump,
                        bool print_diagnostics,
                        std::string *panic_message);

  bool is_enabled_;
  FilePath preserved_dump_path_;
  static const char kClearingSequence[];
};

#endif  // _CRASH_REPORTER_KERNEL_COLLECTOR_H_

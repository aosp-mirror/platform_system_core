/*
 * Copyright (C) 2010 The Android Open Source Project
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

#ifndef CRASH_REPORTER_KERNEL_COLLECTOR_H_
#define CRASH_REPORTER_KERNEL_COLLECTOR_H_

#include <pcrecpp.h>

#include <string>

#include <base/files/file_path.h>
#include <base/macros.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST

#include "crash_collector.h"

// Kernel crash collector.
class KernelCollector : public CrashCollector {
 public:
  // Enumeration to specify architecture type.
  enum ArchKind {
    kArchUnknown,
    kArchArm,
    kArchMips,
    kArchX86,
    kArchX86_64,

    kArchCount  // Number of architectures.
  };

  KernelCollector();

  ~KernelCollector() override;

  void OverridePreservedDumpPath(const base::FilePath &file_path);

  // Enable collection.
  bool Enable();

  // Returns true if the kernel collection currently enabled.
  bool is_enabled() const { return is_enabled_; }

  // Collect any preserved kernel crash dump. Returns true if there was
  // a dump (even if there were problems storing the dump), false otherwise.
  bool Collect();

  // Compute a stack signature string from a kernel dump.
  bool ComputeKernelStackSignature(const std::string &kernel_dump,
                                   std::string *kernel_signature,
                                   bool print_diagnostics);

  // Set the architecture of the crash dumps we are looking at.
  void set_arch(ArchKind arch) { arch_ = arch; }
  ArchKind arch() const { return arch_; }

 private:
  friend class KernelCollectorTest;
  FRIEND_TEST(KernelCollectorTest, LoadPreservedDump);
  FRIEND_TEST(KernelCollectorTest, StripSensitiveDataBasic);
  FRIEND_TEST(KernelCollectorTest, StripSensitiveDataBulk);
  FRIEND_TEST(KernelCollectorTest, StripSensitiveDataSample);
  FRIEND_TEST(KernelCollectorTest, CollectOK);

  virtual bool DumpDirMounted();

  bool LoadPreservedDump(std::string *contents);
  void StripSensitiveData(std::string *kernel_dump);

  void GetRamoopsRecordPath(base::FilePath *path, size_t record);
  bool LoadParameters();
  bool HasMoreRecords();

  // Read a record to string, modified from file_utils since that didn't
  // provide a way to restrict the read length.
  // Return value indicates (only) error state:
  //  * false when we get an error (can't read from dump location).
  //  * true if no error occured.
  // Not finding a valid record is not an error state and is signaled by the
  // record_found output parameter.
  bool ReadRecordToString(std::string *contents,
                          size_t current_record,
                          bool *record_found);

  void ProcessStackTrace(pcrecpp::StringPiece kernel_dump,
                         bool print_diagnostics,
                         unsigned *hash,
                         float *last_stack_timestamp,
                         bool *is_watchdog_crash);
  bool FindCrashingFunction(pcrecpp::StringPiece kernel_dump,
                            bool print_diagnostics,
                            float stack_trace_timestamp,
                            std::string *crashing_function);
  bool FindPanicMessage(pcrecpp::StringPiece kernel_dump,
                        bool print_diagnostics,
                        std::string *panic_message);

  // Returns the architecture kind for which we are built.
  static ArchKind GetCompilerArch();

  bool is_enabled_;
  base::FilePath ramoops_dump_path_;
  size_t records_;

  // The architecture of kernel dump strings we are working with.
  ArchKind arch_;

  DISALLOW_COPY_AND_ASSIGN(KernelCollector);
};

#endif  // CRASH_REPORTER_KERNEL_COLLECTOR_H_

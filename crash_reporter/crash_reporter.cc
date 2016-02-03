/*
 * Copyright (C) 2012 The Android Open Source Project
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

#include <fcntl.h>  // for open

#include <string>
#include <vector>

#include <base/files/file_util.h>
#include <base/guid.h>
#include <base/logging.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <binder/IServiceManager.h>
#include <brillo/flag_helper.h>
#include <brillo/syslog_logging.h>
#include <metrics/metrics_collector_service_client.h>
#include <metrics/metrics_library.h>
#include <utils/String16.h>


#include "kernel_collector.h"
#include "kernel_warning_collector.h"
#include "unclean_shutdown_collector.h"
#include "user_collector.h"

#if !defined(__ANDROID__)
#include "udev_collector.h"
#endif

static const char kCrashCounterHistogram[] = "Logging.CrashCounter";
static const char kKernelCrashDetected[] =
    "/data/misc/crash_reporter/run/kernel-crash-detected";
static const char kUncleanShutdownDetected[] =
    "/var/run/unclean-shutdown-detected";
static const char kGUIDFileName[] = "/data/misc/crash_reporter/guid";

// Enumeration of kinds of crashes to be used in the CrashCounter histogram.
enum CrashKinds {
  kCrashKindUncleanShutdown = 1,
  kCrashKindUser = 2,
  kCrashKindKernel = 3,
  kCrashKindUdev = 4,
  kCrashKindKernelWarning = 5,
  kCrashKindMax
};

static MetricsLibrary s_metrics_lib;

using android::brillo::metrics::IMetricsCollectorService;
using base::FilePath;
using base::StringPrintf;

static bool IsFeedbackAllowed() {
  return s_metrics_lib.AreMetricsEnabled();
}

static bool TouchFile(const FilePath &file_path) {
  return base::WriteFile(file_path, "", 0) == 0;
}

static void SendCrashMetrics(CrashKinds type, const char* name) {
  // TODO(kmixter): We can remove this histogram as part of
  // crosbug.com/11163.
  s_metrics_lib.SendEnumToUMA(kCrashCounterHistogram, type, kCrashKindMax);
  s_metrics_lib.SendCrashToUMA(name);
}

static void CountKernelCrash() {
  SendCrashMetrics(kCrashKindKernel, "kernel");
}

static void CountUdevCrash() {
  SendCrashMetrics(kCrashKindUdev, "udevcrash");
}

static void CountUncleanShutdown() {
  SendCrashMetrics(kCrashKindUncleanShutdown, "uncleanshutdown");
}

static void CountUserCrash() {
  SendCrashMetrics(kCrashKindUser, "user");
  // Tell the metrics collector about the user crash, in order to log active
  // use time between crashes.
  MetricsCollectorServiceClient metrics_collector_service;

  if (metrics_collector_service.Init())
    metrics_collector_service.notifyUserCrash();
  else
    LOG(ERROR) << "Failed to send user crash notification to metrics_collector";
}


static int Initialize(KernelCollector *kernel_collector,
                      UserCollector *user_collector,
                      UncleanShutdownCollector *unclean_shutdown_collector,
                      const bool unclean_check,
                      const bool clean_shutdown) {
  CHECK(!clean_shutdown) << "Incompatible options";

  // Try to read the GUID from kGUIDFileName.  If the file doesn't exist, is
  // blank, or the read fails, generate a new GUID and write it to the file.
  std::string guid;
  base::FilePath filepath(kGUIDFileName);
  if (!base::ReadFileToString(filepath, &guid) || guid.empty()) {
    guid = base::GenerateGUID();
    // If we can't read or write the file, log an error.  However it is not
    // a fatal error, as the crash server will assign a random GUID based
    // on a hash of the IP address if one is not provided in the report.
    if (base::WriteFile(filepath, guid.c_str(), guid.size()) <= 0) {
      LOG(ERROR) << "Could not write guid " << guid << " to file "
                 << filepath.value();
    }
  }

  bool was_kernel_crash = false;
  bool was_unclean_shutdown = false;
  kernel_collector->Enable();
  if (kernel_collector->is_enabled()) {
    was_kernel_crash = kernel_collector->Collect();
  }

  if (unclean_check) {
    was_unclean_shutdown = unclean_shutdown_collector->Collect();
  }

  // Touch a file to notify the metrics daemon that a kernel
  // crash has been detected so that it can log the time since
  // the last kernel crash.
  if (IsFeedbackAllowed()) {
    if (was_kernel_crash) {
      TouchFile(FilePath(kKernelCrashDetected));
    } else if (was_unclean_shutdown) {
      // We only count an unclean shutdown if it did not come with
      // an associated kernel crash.
      TouchFile(FilePath(kUncleanShutdownDetected));
    }
  }

  // Must enable the unclean shutdown collector *after* collecting.
  unclean_shutdown_collector->Enable();
  user_collector->Enable();

  return 0;
}

static int HandleUserCrash(UserCollector *user_collector,
                           const std::string& user, const bool crash_test) {
  // Handle a specific user space crash.
  CHECK(!user.empty()) << "--user= must be set";

  // Make it possible to test what happens when we crash while
  // handling a crash.
  if (crash_test) {
    *(volatile char *)0 = 0;
    return 0;
  }

  // Accumulate logs to help in diagnosing failures during user collection.
  brillo::LogToString(true);
  // Handle the crash, get the name of the process from procfs.
  bool handled = user_collector->HandleCrash(user, nullptr);
  brillo::LogToString(false);
  if (!handled)
    return 1;
  return 0;
}

#if !defined(__ANDROID__)
static int HandleUdevCrash(UdevCollector *udev_collector,
                           const std::string& udev_event) {
  // Handle a crash indicated by a udev event.
  CHECK(!udev_event.empty()) << "--udev= must be set";

  // Accumulate logs to help in diagnosing failures during user collection.
  brillo::LogToString(true);
  bool handled = udev_collector->HandleCrash(udev_event);
  brillo::LogToString(false);
  if (!handled)
    return 1;
  return 0;
}
#endif

static int HandleKernelWarning(KernelWarningCollector
                               *kernel_warning_collector) {
  // Accumulate logs to help in diagnosing failures during collection.
  brillo::LogToString(true);
  bool handled = kernel_warning_collector->Collect();
  brillo::LogToString(false);
  if (!handled)
    return 1;
  return 0;
}

// Interactive/diagnostics mode for generating kernel crash signatures.
static int GenerateKernelSignature(KernelCollector *kernel_collector,
                                   const std::string& kernel_signature_file) {
  std::string kcrash_contents;
  std::string signature;
  if (!base::ReadFileToString(FilePath(kernel_signature_file),
                              &kcrash_contents)) {
    fprintf(stderr, "Could not read file.\n");
    return 1;
  }
  if (!kernel_collector->ComputeKernelStackSignature(
          kcrash_contents,
          &signature,
          true)) {
    fprintf(stderr, "Signature could not be generated.\n");
    return 1;
  }
  printf("Kernel crash signature is \"%s\".\n", signature.c_str());
  return 0;
}

// Ensure stdout, stdin, and stderr are open file descriptors.  If
// they are not, any code which writes to stderr/stdout may write out
// to files opened during execution.  In particular, when
// crash_reporter is run by the kernel coredump pipe handler (via
// kthread_create/kernel_execve), it will not have file table entries
// 1 and 2 (stdout and stderr) populated.  We populate them here.
static void OpenStandardFileDescriptors() {
  int new_fd = -1;
  // We open /dev/null to fill in any of the standard [0, 2] file
  // descriptors.  We leave these open for the duration of the
  // process.  This works because open returns the lowest numbered
  // invalid fd.
  do {
    new_fd = open("/dev/null", 0);
    CHECK_GE(new_fd, 0) << "Unable to open /dev/null";
  } while (new_fd >= 0 && new_fd <= 2);
  close(new_fd);
}

int main(int argc, char *argv[]) {
  DEFINE_bool(init, false, "Initialize crash logging");
  DEFINE_bool(clean_shutdown, false, "Signal clean shutdown");
  DEFINE_string(generate_kernel_signature, "",
                "Generate signature from given kcrash file");
  DEFINE_bool(crash_test, false, "Crash test");
  DEFINE_string(user, "", "User crash info (pid:signal:exec_name)");
  DEFINE_bool(unclean_check, true, "Check for unclean shutdown");

#if !defined(__ANDROID__)
  DEFINE_string(udev, "", "Udev event description (type:device:subsystem)");
#endif

  DEFINE_bool(kernel_warning, false, "Report collected kernel warning");
  DEFINE_string(pid, "", "PID of crashing process");
  DEFINE_string(uid, "", "UID of crashing process");
  DEFINE_string(exe, "", "Executable name of crashing process");
  DEFINE_bool(core2md_failure, false, "Core2md failure test");
  DEFINE_bool(directory_failure, false, "Spool directory failure test");
  DEFINE_string(filter_in, "",
                "Ignore all crashes but this for testing");

  OpenStandardFileDescriptors();
  FilePath my_path = base::MakeAbsoluteFilePath(FilePath(argv[0]));
  s_metrics_lib.Init();
  brillo::FlagHelper::Init(argc, argv, "Chromium OS Crash Reporter");
  brillo::OpenLog(my_path.BaseName().value().c_str(), true);
  brillo::InitLog(brillo::kLogToSyslog);

  KernelCollector kernel_collector;
  kernel_collector.Initialize(CountKernelCrash, IsFeedbackAllowed);
  UserCollector user_collector;
  user_collector.Initialize(CountUserCrash,
                            my_path.value(),
                            IsFeedbackAllowed,
                            true,  // generate_diagnostics
                            FLAGS_core2md_failure,
                            FLAGS_directory_failure,
                            FLAGS_filter_in);
  UncleanShutdownCollector unclean_shutdown_collector;
  unclean_shutdown_collector.Initialize(CountUncleanShutdown,
                                        IsFeedbackAllowed);

#if !defined(__ANDROID__)
  UdevCollector udev_collector;
  udev_collector.Initialize(CountUdevCrash, IsFeedbackAllowed);
#endif

  KernelWarningCollector kernel_warning_collector;
  kernel_warning_collector.Initialize(CountUdevCrash, IsFeedbackAllowed);

  if (FLAGS_init) {
    return Initialize(&kernel_collector,
                      &user_collector,
                      &unclean_shutdown_collector,
                      FLAGS_unclean_check,
                      FLAGS_clean_shutdown);
  }

  if (FLAGS_clean_shutdown) {
    unclean_shutdown_collector.Disable();
    user_collector.Disable();
    return 0;
  }

  if (!FLAGS_generate_kernel_signature.empty()) {
    return GenerateKernelSignature(&kernel_collector,
                                   FLAGS_generate_kernel_signature);
  }

#if !defined(__ANDROID__)
  if (!FLAGS_udev.empty()) {
    return HandleUdevCrash(&udev_collector, FLAGS_udev);
  }
#endif

  if (FLAGS_kernel_warning) {
    return HandleKernelWarning(&kernel_warning_collector);
  }

  return HandleUserCrash(&user_collector, FLAGS_user, FLAGS_crash_test);
}

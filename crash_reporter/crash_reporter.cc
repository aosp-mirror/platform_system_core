// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>

#include "base/file_util.h"
#include "base/logging.h"
#include "base/string_util.h"
#include "crash-reporter/kernel_collector.h"
#include "crash-reporter/system_logging.h"
#include "crash-reporter/unclean_shutdown_collector.h"
#include "crash-reporter/user_collector.h"
#include "gflags/gflags.h"
#include "metrics/metrics_library.h"

#pragma GCC diagnostic ignored "-Wstrict-aliasing"
DEFINE_bool(init, false, "Initialize crash logging");
DEFINE_bool(clean_shutdown, false, "Signal clean shutdown");
DEFINE_bool(crash_test, false, "Crash test");
DEFINE_int32(pid, -1, "Crashing PID");
DEFINE_int32(signal, -1, "Signal causing crash");
DEFINE_bool(unclean_check, true, "Check for unclean shutdown");
#pragma GCC diagnostic error "-Wstrict-aliasing"

static const char kCrashCounterHistogram[] = "Logging.CrashCounter";
static const char kUserCrashSignal[] =
    "org.chromium.CrashReporter.UserCrash";
static const char kUncleanShutdownFile[] =
    "/var/lib/crash_reporter/pending_clean_shutdown";


// Enumeration of kinds of crashes to be used in the CrashCounter histogram.
enum CrashKinds {
  kCrashKindUncleanShutdown = 1,
  kCrashKindUser = 2,
  kCrashKindKernel = 3,
  kCrashKindMax
};

static MetricsLibrary s_metrics_lib;
static SystemLoggingImpl s_system_log;

static bool IsFeedbackAllowed() {
  // Once crosbug.com/5814 is fixed, call the is opted in function
  // here.
  return true;
}

static bool TouchFile(const FilePath &file_path) {
  return file_util::WriteFile(file_path, "", 0) == 0;
}

static void CountKernelCrash() {
  s_metrics_lib.SendEnumToUMA(std::string(kCrashCounterHistogram),
                              kCrashKindKernel,
                              kCrashKindMax);
}

static void CountUncleanShutdown() {
  s_metrics_lib.SendEnumToUMA(std::string(kCrashCounterHistogram),
                              kCrashKindUncleanShutdown,
                              kCrashKindMax);
}

static void CountUserCrash() {
  s_metrics_lib.SendEnumToUMA(std::string(kCrashCounterHistogram),
                              kCrashKindUser,
                              kCrashKindMax);
  std::string command = StringPrintf(
      "/usr/bin/dbus-send --type=signal --system / \"%s\"",
      kUserCrashSignal);
  // Announce through D-Bus whenever a user crash happens. This is
  // used by the metrics daemon to log active use time between
  // crashes.
  //
  // This could be done more efficiently by explicit fork/exec or
  // using a dbus library directly. However, this should run
  // relatively rarely and longer term we may need to implement a
  // better way to do this that doesn't rely on D-Bus.

  int status __attribute__((unused)) = system(command.c_str());
}

static int Initialize(KernelCollector *kernel_collector,
                      UserCollector *user_collector,
                      UncleanShutdownCollector *unclean_shutdown_collector) {
  CHECK(!FLAGS_clean_shutdown) << "Incompatible options";

  bool was_kernel_crash = false;
  bool was_unclean_shutdown = false;
  kernel_collector->Enable();
  if (kernel_collector->IsEnabled()) {
    was_kernel_crash = kernel_collector->Collect();
  }

  if (FLAGS_unclean_check) {
    was_unclean_shutdown = unclean_shutdown_collector->Collect();
  }

  // Touch a file to notify the metrics daemon that a kernel
  // crash has been detected so that it can log the time since
  // the last kernel crash.
  if (IsFeedbackAllowed()) {
    if (was_kernel_crash) {
      TouchFile(FilePath("/tmp/kernel-crash-detected"));
    } else if (was_unclean_shutdown) {
      // We only count an unclean shutdown if it did not come with
      // an associated kernel crash.
      TouchFile(FilePath("/tmp/unclean-shutdown-detected"));
    }
  }

  // Must enable the unclean shutdown collector *after* collecting.
  unclean_shutdown_collector->Enable();
  user_collector->Enable();

  return 0;
}

static int HandleUserCrash(UserCollector *user_collector) {
  // Handle a specific user space crash.
  CHECK(FLAGS_signal != -1) << "Signal must be set";
  CHECK(FLAGS_pid != -1) << "PID must be set";

  // Make it possible to test what happens when we crash while
  // handling a crash.
  if (FLAGS_crash_test) {
    *(char *)0 = 0;
    return 0;
  }

  // Handle the crash, get the name of the process from procfs.
  if (!user_collector->HandleCrash(FLAGS_signal, FLAGS_pid, NULL)) {
    return 1;
  }
  return 0;
}


int main(int argc, char *argv[]) {
  google::ParseCommandLineFlags(&argc, &argv, true);
  FilePath my_path(argv[0]);
  file_util::AbsolutePath(&my_path);
  s_metrics_lib.Init();
  InitLogging(NULL,
              LOG_ONLY_TO_SYSTEM_DEBUG_LOG,
              DONT_LOCK_LOG_FILE,
              DELETE_OLD_LOG_FILE);
  s_system_log.Initialize(my_path.BaseName().value().c_str());
  KernelCollector kernel_collector;
  kernel_collector.Initialize(CountKernelCrash,
                              IsFeedbackAllowed,
                              &s_system_log);
  UserCollector user_collector;
  user_collector.Initialize(CountUserCrash,
                            my_path.value(),
                            IsFeedbackAllowed,
                            &s_system_log,
                            true);  // generate_diagnostics
  UncleanShutdownCollector unclean_shutdown_collector;
  unclean_shutdown_collector.Initialize(CountUncleanShutdown,
                                        IsFeedbackAllowed,
                                        &s_system_log);

  if (FLAGS_init) {
    return Initialize(&kernel_collector,
                      &user_collector,
                      &unclean_shutdown_collector);
  }

  if (FLAGS_clean_shutdown) {
    unclean_shutdown_collector.Disable();
    user_collector.Disable();
    return 0;
  }

  return HandleUserCrash(&user_collector);
}

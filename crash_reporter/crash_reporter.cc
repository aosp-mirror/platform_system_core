// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>

#include "base/file_util.h"
#include "base/command_line.h"
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
DEFINE_string(generate_kernel_signature, "",
              "Generate signature from given kcrash file");
DEFINE_bool(crash_test, false, "Crash test");
DEFINE_string(user, "", "User crash info (pid:signal:exec_name)");
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
  return s_metrics_lib.AreMetricsEnabled();
}

static bool TouchFile(const FilePath &file_path) {
  return file_util::WriteFile(file_path, "", 0) == 0;
}

static void CountKernelCrash() {
  // TODO(kmixter): We can remove this histogram as part of
  // crosbug.com/11163.
  s_metrics_lib.SendEnumToUMA(std::string(kCrashCounterHistogram),
                              kCrashKindKernel,
                              kCrashKindMax);
  s_metrics_lib.SendCrashToUMA("kernel");
}

static void CountUncleanShutdown() {
  // TODO(kmixter): We can remove this histogram as part of
  // crosbug.com/11163.
  s_metrics_lib.SendEnumToUMA(std::string(kCrashCounterHistogram),
                              kCrashKindUncleanShutdown,
                              kCrashKindMax);
  s_metrics_lib.SendCrashToUMA("uncleanshutdown");
}

static void CountUserCrash() {
  // TODO(kmixter): We can remove this histogram as part of
  // crosbug.com/11163.
  s_metrics_lib.SendEnumToUMA(std::string(kCrashCounterHistogram),
                              kCrashKindUser,
                              kCrashKindMax);
  s_metrics_lib.SendCrashToUMA("user");
  std::string command = StringPrintf(
      "/usr/bin/dbus-send --type=signal --system / \"%s\" &",
      kUserCrashSignal);
  // Announce through D-Bus whenever a user crash happens. This is
  // used by the metrics daemon to log active use time between
  // crashes.
  //
  // This could be done more efficiently by explicit fork/exec or
  // using a dbus library directly. However, this should run
  // relatively rarely and longer term we may need to implement a
  // better way to do this that doesn't rely on D-Bus.
  //
  // We run in the background in case dbus daemon itself is crashed
  // and not responding.  This allows us to not block and potentially
  // deadlock on a dbus-daemon crash.  If dbus-daemon crashes without
  // restarting, each crash will fork off a lot of dbus-send
  // processes.  Such a system is in a unusable state and will need
  // to be restarted anyway.

  int status = system(command.c_str());
  if (status != 0) {
    s_system_log.LogWarning("dbus-send running failed");
  }
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
  CHECK(!FLAGS_user.empty()) << "--user= must be set";

  // Make it possible to test what happens when we crash while
  // handling a crash.
  if (FLAGS_crash_test) {
    *(char *)0 = 0;
    return 0;
  }

  // Accumulate logs to help in diagnosing failures during user collection.
  s_system_log.set_accumulating(true);
  // Handle the crash, get the name of the process from procfs.
  bool handled = user_collector->HandleCrash(FLAGS_user, NULL);
  s_system_log.set_accumulating(false);
  if (!handled)
    return 1;
  return 0;
}

// Interactive/diagnostics mode for generating kernel crash signatures.
static int GenerateKernelSignature(KernelCollector *kernel_collector) {
  std::string kcrash_contents;
  std::string signature;
  if (!file_util::ReadFileToString(FilePath(FLAGS_generate_kernel_signature),
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

int main(int argc, char *argv[]) {
  google::ParseCommandLineFlags(&argc, &argv, true);
  FilePath my_path(argv[0]);
  file_util::AbsolutePath(&my_path);
  s_metrics_lib.Init();
  CommandLine::Init(argc, argv);
  logging::InitLogging(NULL,
                       logging::LOG_ONLY_TO_SYSTEM_DEBUG_LOG,
                       logging::DONT_LOCK_LOG_FILE,
                       logging::DELETE_OLD_LOG_FILE);
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

  if (!FLAGS_generate_kernel_signature.empty()) {
    return GenerateKernelSignature(&kernel_collector);
  }

  return HandleUserCrash(&user_collector);
}

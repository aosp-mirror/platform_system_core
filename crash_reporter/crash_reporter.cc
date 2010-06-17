// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>

#include "base/file_util.h"
#include "base/logging.h"
#include "base/string_util.h"
#include "crash/system_logging.h"
#include "crash/user_collector.h"
#include "gflags/gflags.h"
#include "metrics/metrics_library.h"

#pragma GCC diagnostic ignored "-Wstrict-aliasing"
DEFINE_bool(init, false, "Initialize crash logging");
DEFINE_bool(clean_shutdown, false, "Signal clean shutdown");
DEFINE_bool(crash_test, false, "Crash test");
DEFINE_string(exec, "", "Executable name crashed");
DEFINE_int32(pid, -1, "Crashing PID");
DEFINE_int32(signal, -1, "Signal causing crash");
DEFINE_bool(unclean_check, true, "Check for unclean shutdown");
#pragma GCC diagnostic error "-Wstrict-aliasing"

static const char kCrashCounterHistogram[] = "Logging.CrashCounter";
static const char kUncleanShutdownFile[] =
    "/var/lib/crash_reporter/pending_clean_shutdown";

// Enumeration of kinds of crashes to be used in the CrashCounter histogram.
enum CrashKinds {
  CRASH_KIND_KERNEL = 1,
  CRASH_KIND_USER   = 2,
  CRASH_KIND_MAX
};

static MetricsLibrary s_metrics_lib;
static SystemLoggingImpl s_system_log;

static bool IsMetricsCollectionAllowed() {
  // TODO(kmixter): Eventually check system tainted state and
  // move this down in metrics library where it would be explicitly
  // checked when asked to send stats.
  return true;
}

static void CheckUncleanShutdown() {
  FilePath unclean_file_path(kUncleanShutdownFile);
  if (!file_util::PathExists(unclean_file_path)) {
    return;
  }
  s_system_log.LogWarning("Last shutdown was not clean");
  if (IsMetricsCollectionAllowed()) {
    s_metrics_lib.SendEnumToUMA(std::string(kCrashCounterHistogram),
                                CRASH_KIND_KERNEL,
                                CRASH_KIND_MAX);
  }
  if (!file_util::Delete(unclean_file_path, false)) {
    s_system_log.LogError("Failed to delete unclean shutdown file %s",
                          kUncleanShutdownFile);
  }
}

static bool PrepareUncleanShutdownCheck() {
  static const char empty[] = "";
  FilePath file_path(kUncleanShutdownFile);
  file_util::CreateDirectory(file_path.DirName());
  return file_util::WriteFile(file_path, empty, 0) == 0;
}

static void SignalCleanShutdown() {
  s_system_log.LogInfo("Clean shutdown signalled");
  file_util::Delete(FilePath(kUncleanShutdownFile), false);
}

static void CountUserCrash() {
  CHECK(IsMetricsCollectionAllowed());
  s_metrics_lib.SendEnumToUMA(std::string(kCrashCounterHistogram),
                              CRASH_KIND_USER,
                              CRASH_KIND_MAX);

  // Announce through D-Bus whenever a user crash happens. This is
  // used by the metrics daemon to log active use time between
  // crashes.
  //
  // This could be done more efficiently by explicit fork/exec or
  // using a dbus library directly. However, this should run
  // relatively rarely and longer term we may need to implement a
  // better way to do this that doesn't rely on D-Bus.
  int status __attribute__((unused)) =
      system("/usr/bin/dbus-send --type=signal --system / "
             "org.chromium.CrashReporter.UserCrash");
}

int main(int argc, char *argv[]) {
  google::ParseCommandLineFlags(&argc, &argv, true);
  FilePath my_path(argv[0]);
  file_util::AbsolutePath(&my_path);
  s_metrics_lib.Init();
  s_system_log.Initialize(my_path.BaseName().value().c_str());
  UserCollector user_collector;
  user_collector.Initialize(CountUserCrash,
                            my_path.value(),
                            IsMetricsCollectionAllowed,
                            &s_system_log);

  if (FLAGS_init) {
    CHECK(!FLAGS_clean_shutdown) << "Incompatible options";
    user_collector.Enable();
    if (FLAGS_unclean_check) {
      CheckUncleanShutdown();
      if (!PrepareUncleanShutdownCheck()) {
        s_system_log.LogError("Unable to create shutdown check file");
      }
    }
    return 0;
  }

  if (FLAGS_clean_shutdown) {
    SignalCleanShutdown();
    user_collector.Disable();
    return 0;
  }

  // Handle a specific user space crash.
  CHECK(FLAGS_signal != -1) << "Signal must be set";
  CHECK(FLAGS_pid != -1) << "PID must be set";
  CHECK(FLAGS_exec != "") << "Executable name must be set";

  // Make it possible to test what happens when we crash while
  // handling a crash.
  if (FLAGS_crash_test) {
    *(char *)0 = 0;
    return 0;
  }

  user_collector.HandleCrash(FLAGS_signal, FLAGS_pid, FLAGS_exec);

  return 0;
}

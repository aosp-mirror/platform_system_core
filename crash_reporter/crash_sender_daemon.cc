// Copyright 2014 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/crash_sender_daemon.h"

#include <unistd.h>

#include <base/at_exit.h>
#include <base/bind.h>
#include <base/command_line.h>
#include <base/logging.h>
#include <base/run_loop.h>
#include <chromeos/syslog_logging.h>
#include <crash-reporter/crash_sender_service.h>
#include <dbus/bus.h>

namespace {
// Parameter to specify a custom config file.
const char kSwitchCustomConfigFile[] = "config";

const char kDefaultConfigFile[] = "/etc/crash_sender.conf";

const int kTerminationSignals[] = { SIGTERM, SIGINT };
const int kNumTerminationSignals = arraysize(kTerminationSignals);
}  // namespace


namespace crash_reporter {
CrashSenderDaemon::CrashSenderDaemon(const base::FilePath& config_file)
    : config_file_(config_file) {}

CrashSenderDaemon::~CrashSenderDaemon() {
}

void CrashSenderDaemon::Run() {
  base::RunLoop loop;
  dbus::Bus::Options options;
  options.bus_type = dbus::Bus::SYSTEM;
  options.disconnected_callback = loop.QuitClosure();

  scoped_refptr<dbus::Bus> bus = new dbus::Bus(options);
  CrashSenderConfiguration config =
      CrashSenderService::ParseConfiguration(config_file_);
  scoped_ptr<DbusCrashSenderServiceImpl> impl(
      new DbusCrashSenderServiceImpl(config));

  CHECK(impl->Start(bus)) << "Failed to start crash sender service";
  crash_sender_service_ = impl.Pass();

  for (size_t i = 0; i < kNumTerminationSignals; ++i) {
    async_signal_handler_.RegisterHandler(
        kTerminationSignals[i],
        base::Bind(&CrashSenderDaemon::Shutdown, base::Unretained(this)));
  }
  async_signal_handler_.RegisterHandler(
      SIGHUP, base::Bind(&CrashSenderDaemon::Restart, base::Unretained(this)));
  async_signal_handler_.Init();

  loop.Run();

  bus->ShutdownAndBlock();
}

bool CrashSenderDaemon::Shutdown(const struct signalfd_siginfo& info) {
  loop_.PostTask(FROM_HERE, loop_.QuitClosure());
  // Unregister the signal handler.
  return true;
}

bool CrashSenderDaemon::Restart(const struct signalfd_siginfo& info) {
  CrashSenderConfiguration config =
      CrashSenderService::ParseConfiguration(config_file_);
  crash_sender_service_->Restart(config);
  // Keep listening to the signal.
  return false;
}

}  // namespace crash_reporter

int main(int argc, char** argv) {
  CommandLine::Init(argc, argv);
  CommandLine* args = CommandLine::ForCurrentProcess();

  // Some libchrome calls need this.
  base::AtExitManager at_exit_manager;

  chromeos::InitLog(chromeos::kLogToSyslog | chromeos::kLogToStderr);

  base::FilePath config_file =
      args->GetSwitchValuePath(kSwitchCustomConfigFile);
  if (config_file.empty()) {
    config_file = base::FilePath(FILE_PATH_LITERAL(kDefaultConfigFile));
  } else {
    LOG(INFO) << "Using crash configuration at: " << config_file.value();
  }

  crash_reporter::CrashSenderDaemon daemon(config_file);
  daemon.Run();
  return 0;
}

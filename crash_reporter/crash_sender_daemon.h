// Copyright 2014 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRASH_REPORTER_CRASH_SENDER_DAEMON_H_
#define CRASH_REPORTER_CRASH_SENDER_DAEMON_H_

#include <base/files/file_path.h>
#include <base/memory/scoped_ptr.h>
#include <base/message_loop/message_loop.h>
#include <chromeos/asynchronous_signal_handler.h>

#include "crash-reporter/crash_sender_service.h"

namespace crash_reporter {

class CrashSenderDaemon {
 public:
  // |config_file| specifies the config file for the crash sender.
  explicit CrashSenderDaemon(const base::FilePath& config_file);
  ~CrashSenderDaemon();

  // Does all the work. Blocks until the daemon is finished.
  void Run();

 private:
  base::MessageLoopForIO loop_;
  base::FilePath config_file_;
  scoped_ptr<CrashSenderService> crash_sender_service_;
  chromeos::AsynchronousSignalHandler async_signal_handler_;

  // Shutdown the sender.
  bool Shutdown(const signalfd_siginfo& info);

  // Restart the service, reading the configuration file again.
  bool Restart(const signalfd_siginfo& info);

  DISALLOW_COPY_AND_ASSIGN(CrashSenderDaemon);
};

}  // namespace crash_reporter

#endif  // CRASH_REPORTER_CRASH_SENDER_DAEMON_H_

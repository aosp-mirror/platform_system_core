/*
 * Copyright 2016, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <limits>
#include <string_view>
#include <thread>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/unique_fd.h>
#include <debuggerd/client.h>
#include <procinfo/process.h>
#include "util.h"

using android::base::unique_fd;

static void usage(int exit_code) {
  fprintf(stderr, "usage: debuggerd [-bj] PID\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "-b, --backtrace    just a backtrace rather than a full tombstone\n");
  fprintf(stderr, "-j                 collect java traces\n");
  _exit(exit_code);
}

int main(int argc, char* argv[]) {
  if (argc <= 1) usage(0);
  if (argc > 3) usage(1);

  DebuggerdDumpType dump_type = kDebuggerdTombstone;

  if (argc == 3) {
    std::string_view flag = argv[1];
    if (flag == "-b" || flag == "--backtrace") {
      dump_type = kDebuggerdNativeBacktrace;
    } else if (flag == "-j") {
      dump_type = kDebuggerdJavaBacktrace;
    } else {
      usage(1);
    }
  }

  pid_t pid;
  if (!android::base::ParseInt(argv[argc - 1], &pid, 1, std::numeric_limits<pid_t>::max())) {
    usage(1);
  }

  if (getuid() != 0) {
    errx(1, "root is required");
  }

  // Check to see if the process exists and that we can actually send a signal to it.
  android::procinfo::ProcessInfo proc_info;
  if (!android::procinfo::GetProcessInfo(pid, &proc_info)) {
    err(1, "failed to fetch info for process %d", pid);
  }

  if (proc_info.state == android::procinfo::kProcessStateZombie) {
    errx(1, "process %d is a zombie", pid);
  }

  // Send a signal to the main thread pid, not a side thread. The signal
  // handler always sets the crashing tid to the main thread pid when sent this
  // signal. This is to avoid a problem where the signal is sent to a process,
  // but happens on a side thread and the intercept mismatches since it
  // is looking for the main thread pid, not the tid of this random thread.
  // See b/194346289 for extra details.
  if (kill(proc_info.pid, 0) != 0) {
    if (pid == proc_info.pid) {
      err(1, "cannot send signal to process %d", pid);
    } else {
      err(1, "cannot send signal to main thread %d (requested thread %d)", proc_info.pid, pid);
    }
  }

  // unfreeze if pid is frozen.
  const std::string freeze_file = android::base::StringPrintf(
      "/sys/fs/cgroup/uid_%d/pid_%d/cgroup.freeze", proc_info.uid, proc_info.pid);
  if (std::string freeze_status;
      android::base::ReadFileToString(freeze_file, &freeze_status) && freeze_status[0] == '1') {
    android::base::WriteStringToFile("0", freeze_file);
    // we don't restore the frozen state as this is considered a benign change.
  }

  unique_fd output_fd(fcntl(STDOUT_FILENO, F_DUPFD_CLOEXEC, 0));
  if (output_fd.get() == -1) {
    err(1, "failed to fcntl dup stdout");
  }
  if (!debuggerd_trigger_dump(proc_info.pid, dump_type, 0, std::move(output_fd))) {
    if (pid == proc_info.pid) {
      errx(1, "failed to dump process %d", pid);
    } else {
      errx(1, "failed to dump main thread %d (requested thread %d)", proc_info.pid, pid);
    }
  }

  return 0;
}

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
  fprintf(stderr, "usage: debuggerd [-b] PID\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "-b, --backtrace    just a backtrace rather than a full tombstone\n");
  _exit(exit_code);
}

static std::thread spawn_redirect_thread(unique_fd fd) {
  return std::thread([fd{ std::move(fd) }]() {
    while (true) {
      char buf[BUFSIZ];
      ssize_t rc = TEMP_FAILURE_RETRY(read(fd.get(), buf, sizeof(buf)));
      if (rc <= 0) {
        return;
      }

      if (!android::base::WriteFully(STDOUT_FILENO, buf, rc)) {
        return;
      }
    }
  });
}

int main(int argc, char* argv[]) {
  if (argc <= 1) usage(0);
  if (argc > 3) usage(1);
  if (argc == 3 && strcmp(argv[1], "-b") != 0 && strcmp(argv[1], "--backtrace") != 0) usage(1);
  bool backtrace_only = argc == 3;

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

  if (kill(pid, 0) != 0) {
    err(1, "cannot send signal to process %d", pid);
  }

  unique_fd piperead, pipewrite;
  if (!Pipe(&piperead, &pipewrite)) {
    err(1, "failed to create pipe");
  }

  std::thread redirect_thread = spawn_redirect_thread(std::move(piperead));
  if (!debuggerd_trigger_dump(pid, backtrace_only ? kDebuggerdNativeBacktrace : kDebuggerdTombstone,
                              0, std::move(pipewrite))) {
    redirect_thread.join();
    errx(1, "failed to dump process %d", pid);
  }

  redirect_thread.join();
  return 0;
}

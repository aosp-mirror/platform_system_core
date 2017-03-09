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

#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/un.h>
#include <syscall.h>
#include <unistd.h>

#include <limits>
#include <memory>
#include <set>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/unique_fd.h>
#include <cutils/sockets.h>
#include <log/log.h>
#include <procinfo/process.h>
#include <selinux/selinux.h>

#include "backtrace.h"
#include "tombstone.h"
#include "utility.h"

#include "debuggerd/handler.h"
#include "debuggerd/protocol.h"
#include "debuggerd/tombstoned.h"
#include "debuggerd/util.h"

using android::base::unique_fd;
using android::base::StringPrintf;

static bool pid_contains_tid(int pid_proc_fd, pid_t tid) {
  struct stat st;
  std::string task_path = StringPrintf("task/%d", tid);
  return fstatat(pid_proc_fd, task_path.c_str(), &st, 0) == 0;
}

// Attach to a thread, and verify that it's still a member of the given process
static bool ptrace_seize_thread(int pid_proc_fd, pid_t tid, std::string* error) {
  if (ptrace(PTRACE_SEIZE, tid, 0, 0) != 0) {
    *error = StringPrintf("failed to attach to thread %d: %s", tid, strerror(errno));
    return false;
  }

  // Make sure that the task we attached to is actually part of the pid we're dumping.
  if (!pid_contains_tid(pid_proc_fd, tid)) {
    if (ptrace(PTRACE_DETACH, tid, 0, 0) != 0) {
      PLOG(FATAL) << "failed to detach from thread " << tid;
    }
    *error = StringPrintf("thread %d is not in process", tid);
    return false;
  }

  // Put the task into ptrace-stop state.
  if (ptrace(PTRACE_INTERRUPT, tid, 0, 0) != 0) {
    PLOG(FATAL) << "failed to interrupt thread " << tid;
  }

  return true;
}

static bool activity_manager_notify(int pid, int signal, const std::string& amfd_data) {
  android::base::unique_fd amfd(socket_local_client("/data/system/ndebugsocket", ANDROID_SOCKET_NAMESPACE_FILESYSTEM, SOCK_STREAM));
  if (amfd.get() == -1) {
    PLOG(ERROR) << "unable to connect to activity manager";
    return false;
  }

  struct timeval tv = {
    .tv_sec = 1,
    .tv_usec = 0,
  };
  if (setsockopt(amfd.get(), SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) == -1) {
    PLOG(ERROR) << "failed to set send timeout on activity manager socket";
    return false;
  }
  tv.tv_sec = 3;  // 3 seconds on handshake read
  if (setsockopt(amfd.get(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == -1) {
    PLOG(ERROR) << "failed to set receive timeout on activity manager socket";
    return false;
  }

  // Activity Manager protocol: binary 32-bit network-byte-order ints for the
  // pid and signal number, followed by the raw text of the dump, culminating
  // in a zero byte that marks end-of-data.
  uint32_t datum = htonl(pid);
  if (!android::base::WriteFully(amfd, &datum, 4)) {
    PLOG(ERROR) << "AM pid write failed";
    return false;
  }
  datum = htonl(signal);
  if (!android::base::WriteFully(amfd, &datum, 4)) {
    PLOG(ERROR) << "AM signal write failed";
    return false;
  }
  if (!android::base::WriteFully(amfd, amfd_data.c_str(), amfd_data.size() + 1)) {
    PLOG(ERROR) << "AM data write failed";
    return false;
  }

  // 3 sec timeout reading the ack; we're fine if the read fails.
  char ack;
  android::base::ReadFully(amfd, &ack, 1);
  return true;
}

static void signal_handler(int) {
  // We can't log easily, because the heap might be corrupt.
  // Just die and let the surrounding log context explain things.
  _exit(1);
}

static void abort_handler(pid_t target, const bool& tombstoned_connected,
                          unique_fd& tombstoned_socket, unique_fd& output_fd,
                          const char* abort_msg) {
  // If we abort before we get an output fd, contact tombstoned to let any
  // potential listeners know that we failed.
  if (!tombstoned_connected) {
    if (!tombstoned_connect(target, &tombstoned_socket, &output_fd)) {
      // We failed to connect, not much we can do.
      LOG(ERROR) << "failed to connected to tombstoned to report failure";
      _exit(1);
    }
  }

  dprintf(output_fd.get(), "crash_dump failed to dump process %d: %s\n", target, abort_msg);

  _exit(1);
}

static void drop_capabilities() {
  __user_cap_header_struct capheader;
  memset(&capheader, 0, sizeof(capheader));
  capheader.version = _LINUX_CAPABILITY_VERSION_3;
  capheader.pid = 0;

  __user_cap_data_struct capdata[2];
  memset(&capdata, 0, sizeof(capdata));

  if (capset(&capheader, &capdata[0]) == -1) {
    PLOG(FATAL) << "failed to drop capabilities";
  }

  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
    PLOG(FATAL) << "failed to set PR_SET_NO_NEW_PRIVS";
  }
}

int main(int argc, char** argv) {
  pid_t target = getppid();
  bool tombstoned_connected = false;
  unique_fd tombstoned_socket;
  unique_fd output_fd;

  android::base::InitLogging(argv);
  android::base::SetAborter([&](const char* abort_msg) {
    abort_handler(target, tombstoned_connected, tombstoned_socket, output_fd, abort_msg);
  });

  // Don't try to dump ourselves.
  struct sigaction action = {};
  action.sa_handler = signal_handler;
  debuggerd_register_handlers(&action);

  if (argc != 3) {
    return 1;
  }

  pid_t main_tid;
  pid_t pseudothread_tid;

  if (target == 1) {
    LOG(FATAL) << "target died before we could attach";
  }

  if (!android::base::ParseInt(argv[1], &main_tid, 1, std::numeric_limits<pid_t>::max())) {
    LOG(FATAL) << "invalid main tid: " << argv[1];
  }

  if (!android::base::ParseInt(argv[2], &pseudothread_tid, 1, std::numeric_limits<pid_t>::max())) {
    LOG(FATAL) << "invalid pseudothread tid: " << argv[2];
  }

  android::procinfo::ProcessInfo target_info;
  if (!android::procinfo::GetProcessInfo(main_tid, &target_info)) {
    LOG(FATAL) << "failed to fetch process info for target " << main_tid;
  }

  if (main_tid != target_info.tid || target != target_info.pid) {
    LOG(FATAL) << "target info mismatch, expected pid " << target << ", tid " << main_tid
               << ", received pid " << target_info.pid << ", tid " << target_info.tid;
  }

  // Open /proc/`getppid()` in the original process, and pass it down to the forked child.
  std::string target_proc_path = "/proc/" + std::to_string(target);
  int target_proc_fd = open(target_proc_path.c_str(), O_DIRECTORY | O_RDONLY);
  if (target_proc_fd == -1) {
    PLOG(FATAL) << "failed to open " << target_proc_path;
  }

  // Make sure our parent didn't die.
  if (getppid() != target) {
    PLOG(FATAL) << "parent died";
  }

  // Reparent ourselves to init, so that the signal handler can waitpid on the
  // original process to avoid leaving a zombie for non-fatal dumps.
  pid_t forkpid = fork();
  if (forkpid == -1) {
    PLOG(FATAL) << "fork failed";
  } else if (forkpid != 0) {
    exit(0);
  }

  // Die if we take too long.
  alarm(20);

  std::string attach_error;

  // Seize the main thread.
  if (!ptrace_seize_thread(target_proc_fd, main_tid, &attach_error)) {
    LOG(FATAL) << attach_error;
  }

  // Seize the siblings.
  std::set<pid_t> attached_siblings;
  {
    std::set<pid_t> siblings;
    if (!android::procinfo::GetProcessTids(target, &siblings)) {
      PLOG(FATAL) << "failed to get process siblings";
    }

    // but not the already attached main thread.
    siblings.erase(main_tid);
    // or the handler pseudothread.
    siblings.erase(pseudothread_tid);

    for (pid_t sibling_tid : siblings) {
      if (!ptrace_seize_thread(target_proc_fd, sibling_tid, &attach_error)) {
        LOG(WARNING) << attach_error;
      } else {
        attached_siblings.insert(sibling_tid);
      }
    }
  }

  // Collect the backtrace map and open files, while the process still has PR_GET_DUMPABLE=1
  std::unique_ptr<BacktraceMap> backtrace_map(BacktraceMap::Create(main_tid));
  if (!backtrace_map) {
    LOG(FATAL) << "failed to create backtrace map";
  }

  // Collect the list of open files.
  OpenFilesList open_files;
  populate_open_files_list(target, &open_files);

  // Drop our capabilities now that we've attached to the threads we care about.
  drop_capabilities();

  LOG(INFO) << "obtaining output fd from tombstoned";
  tombstoned_connected = tombstoned_connect(target, &tombstoned_socket, &output_fd);

  // Write a '\1' to stdout to tell the crashing process to resume.
  // It also restores the value of PR_SET_DUMPABLE at this point.
  if (TEMP_FAILURE_RETRY(write(STDOUT_FILENO, "\1", 1)) == -1) {
    PLOG(ERROR) << "failed to communicate to target process";
  }

  if (tombstoned_connected) {
    if (TEMP_FAILURE_RETRY(dup2(output_fd.get(), STDOUT_FILENO)) == -1) {
      PLOG(ERROR) << "failed to dup2 output fd (" << output_fd.get() << ") to STDOUT_FILENO";
    }
  } else {
    unique_fd devnull(TEMP_FAILURE_RETRY(open("/dev/null", O_RDWR)));
    TEMP_FAILURE_RETRY(dup2(devnull.get(), STDOUT_FILENO));
    output_fd = std::move(devnull);
  }

  LOG(INFO) << "performing dump of process " << target << " (target tid = " << main_tid << ")";

  // At this point, the thread that made the request has been attached and is
  // in ptrace-stopped state. After resumption, the triggering signal that has
  // been queued will be delivered.
  if (ptrace(PTRACE_CONT, main_tid, 0, 0) != 0) {
    PLOG(ERROR) << "PTRACE_CONT(" << main_tid << ") failed";
    exit(1);
  }

  siginfo_t siginfo = {};
  if (!wait_for_signal(main_tid, &siginfo)) {
    printf("failed to wait for signal in tid %d: %s\n", main_tid, strerror(errno));
    exit(1);
  }

  int signo = siginfo.si_signo;
  bool fatal_signal = signo != DEBUGGER_SIGNAL;
  bool backtrace = false;
  uintptr_t abort_address = 0;

  // si_value can represent three things:
  //   0: dump tombstone
  //   1: dump backtrace
  //   everything else: abort message address (implies dump tombstone)
  if (siginfo.si_value.sival_int == 1) {
    backtrace = true;
  } else if (siginfo.si_value.sival_ptr != nullptr) {
    abort_address = reinterpret_cast<uintptr_t>(siginfo.si_value.sival_ptr);
  }

  // TODO: Use seccomp to lock ourselves down.

  std::string amfd_data;
  if (backtrace) {
    dump_backtrace(output_fd.get(), backtrace_map.get(), target, main_tid, attached_siblings, 0);
  } else {
    engrave_tombstone(output_fd.get(), backtrace_map.get(), &open_files, target, main_tid,
                      &attached_siblings, abort_address, fatal_signal ? &amfd_data : nullptr);
  }

  // We don't actually need to PTRACE_DETACH, as long as our tracees aren't in
  // group-stop state, which is true as long as no stopping signals are sent.

  bool wait_for_gdb = android::base::GetBoolProperty("debug.debuggerd.wait_for_gdb", false);
  if (!fatal_signal || siginfo.si_code == SI_USER) {
    // Don't wait_for_gdb when the process didn't actually crash.
    wait_for_gdb = false;
  }

  // If the process crashed or we need to send it SIGSTOP for wait_for_gdb,
  // get it in a state where it can receive signals, and then send the relevant
  // signal.
  if (wait_for_gdb || fatal_signal) {
    if (ptrace(PTRACE_INTERRUPT, main_tid, 0, 0) != 0) {
      PLOG(ERROR) << "failed to use PTRACE_INTERRUPT on " << main_tid;
    }

    if (tgkill(target, main_tid, wait_for_gdb ? SIGSTOP : signo) != 0) {
      PLOG(ERROR) << "failed to resend signal " << signo << " to " << main_tid;
    }
  }

  if (wait_for_gdb) {
    // Use ALOGI to line up with output from engrave_tombstone.
    ALOGI(
      "***********************************************************\n"
      "* Process %d has been suspended while crashing.\n"
      "* To attach gdbserver and start gdb, run this on the host:\n"
      "*\n"
      "*     gdbclient.py -p %d\n"
      "*\n"
      "***********************************************************",
      target, main_tid);
  }

  if (fatal_signal) {
    activity_manager_notify(target, signo, amfd_data);
  }

  // Close stdout before we notify tombstoned of completion.
  close(STDOUT_FILENO);
  if (tombstoned_connected && !tombstoned_notify_completion(tombstoned_socket.get())) {
    LOG(ERROR) << "failed to notify tombstoned of completion";
  }

  return 0;
}

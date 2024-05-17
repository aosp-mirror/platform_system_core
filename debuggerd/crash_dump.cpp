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
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdint>
#include <limits>
#include <map>
#include <memory>
#include <set>
#include <vector>

#include <android-base/errno_restorer.h>
#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/macros.h>
#include <android-base/parseint.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <bionic/macros.h>
#include <bionic/reserved_signals.h>
#include <bionic/tls_defines.h>
#include <cutils/sockets.h>
#include <log/log.h>
#include <private/android_filesystem_config.h>
#include <procinfo/process.h>

#define ATRACE_TAG ATRACE_TAG_BIONIC
#include <utils/Trace.h>

#include <unwindstack/AndroidUnwinder.h>
#include <unwindstack/Error.h>
#include <unwindstack/MachineArm.h>
#include <unwindstack/MachineArm64.h>
#include <unwindstack/MachineRiscv64.h>
#include <unwindstack/Regs.h>
#include <unwindstack/RegsArm.h>
#include <unwindstack/RegsArm64.h>
#include <unwindstack/RegsRiscv64.h>
#include <unwindstack/UserArm.h>
#include <unwindstack/UserArm64.h>
#include <unwindstack/UserRiscv64.h>

#include <native_bridge_support/guest_state_accessor/accessor.h>

#include "libdebuggerd/backtrace.h"
#include "libdebuggerd/tombstone.h"
#include "libdebuggerd/utility.h"

#include "debuggerd/handler.h"
#include "tombstone_handler.h"

#include "protocol.h"
#include "util.h"

using android::base::ErrnoRestorer;
using android::base::StringPrintf;
using android::base::unique_fd;

// This stores guest architecture. When the architecture is supported, tombstone file will output
// guest state information.
static Architecture g_guest_arch;

static bool pid_contains_tid(int pid_proc_fd, pid_t tid) {
  struct stat st;
  std::string task_path = StringPrintf("task/%d", tid);
  return fstatat(pid_proc_fd, task_path.c_str(), &st, 0) == 0;
}

static pid_t get_tracer(pid_t tracee) {
  // Check to see if the thread is being ptraced by another process.
  android::procinfo::ProcessInfo process_info;
  if (android::procinfo::GetProcessInfo(tracee, &process_info)) {
    return process_info.tracer;
  }
  return -1;
}

// Attach to a thread, and verify that it's still a member of the given process
static bool ptrace_seize_thread(int pid_proc_fd, pid_t tid, std::string* error, int flags = 0) {
  if (ptrace(PTRACE_SEIZE, tid, 0, flags) != 0) {
    if (errno == EPERM) {
      ErrnoRestorer errno_restorer;  // In case get_tracer() fails and we fall through.
      pid_t tracer_pid = get_tracer(tid);
      if (tracer_pid > 0) {
        *error = StringPrintf("failed to attach to thread %d, already traced by %d (%s)", tid,
                              tracer_pid, get_process_name(tracer_pid).c_str());
        return false;
      }
    }

    *error = StringPrintf("failed to attach to thread %d: %s", tid, strerror(errno));
    return false;
  }

  // Make sure that the task we attached to is actually part of the pid we're dumping.
  if (!pid_contains_tid(pid_proc_fd, tid)) {
    if (ptrace(PTRACE_DETACH, tid, 0, 0) != 0) {
      PLOG(WARNING) << "failed to detach from thread " << tid;
    }
    *error = StringPrintf("thread %d is not in process", tid);
    return false;
  }

  return true;
}

static bool wait_for_stop(pid_t tid, int* received_signal) {
  while (true) {
    int status;
    pid_t result = waitpid(tid, &status, __WALL);
    if (result != tid) {
      PLOG(ERROR) << "waitpid failed on " << tid << " while detaching";
      return false;
    }

    if (WIFSTOPPED(status)) {
      if (status >> 16 == PTRACE_EVENT_STOP) {
        *received_signal = 0;
      } else {
        *received_signal = WSTOPSIG(status);
      }
      return true;
    }
  }
}

// Interrupt a process and wait for it to be interrupted.
static bool ptrace_interrupt(pid_t tid, int* received_signal) {
  if (ptrace(PTRACE_INTERRUPT, tid, 0, 0) == 0) {
    return wait_for_stop(tid, received_signal);
  }

  PLOG(ERROR) << "failed to interrupt " << tid << " to detach";
  return false;
}

static bool activity_manager_notify(pid_t pid, int signal, const std::string& amfd_data,
                                    bool recoverable_crash) {
  ATRACE_CALL();
  android::base::unique_fd amfd(socket_local_client(
      "/data/system/ndebugsocket", ANDROID_SOCKET_NAMESPACE_FILESYSTEM, SOCK_STREAM));
  if (amfd.get() == -1) {
    PLOG(ERROR) << "unable to connect to activity manager";
    return false;
  }

  struct timeval tv = {
      .tv_sec = 1 * android::base::HwTimeoutMultiplier(),
      .tv_usec = 0,
  };
  if (setsockopt(amfd.get(), SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) == -1) {
    PLOG(ERROR) << "failed to set send timeout on activity manager socket";
    return false;
  }
  tv.tv_sec = 3 * android::base::HwTimeoutMultiplier();  // 3 seconds on handshake read
  if (setsockopt(amfd.get(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == -1) {
    PLOG(ERROR) << "failed to set receive timeout on activity manager socket";
    return false;
  }

  // Activity Manager protocol:
  //  - 32-bit network-byte-order: pid
  //  - 32-bit network-byte-order: signal number
  //  - byte: recoverable_crash
  //  - bytes: raw text of the dump
  //  - null terminator

  uint32_t datum = htonl(pid);
  if (!android::base::WriteFully(amfd, &datum, sizeof(datum))) {
    PLOG(ERROR) << "AM pid write failed";
    return false;
  }

  datum = htonl(signal);
  if (!android::base::WriteFully(amfd, &datum, sizeof(datum))) {
    PLOG(ERROR) << "AM signo write failed";
    return false;
  }

  uint8_t recoverable_crash_byte = recoverable_crash ? 1 : 0;
  if (!android::base::WriteFully(amfd, &recoverable_crash_byte, sizeof(recoverable_crash_byte))) {
    PLOG(ERROR) << "AM recoverable_crash_byte write failed";
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

// Globals used by the abort handler.
static pid_t g_target_thread = -1;
static bool g_tombstoned_connected = false;
static unique_fd g_tombstoned_socket;
static unique_fd g_output_fd;
static unique_fd g_proto_fd;

static void DefuseSignalHandlers() {
  // Don't try to dump ourselves.
  struct sigaction action = {};
  action.sa_handler = SIG_DFL;
  debuggerd_register_handlers(&action);

  sigset_t mask;
  sigemptyset(&mask);
  if (sigprocmask(SIG_SETMASK, &mask, nullptr) != 0) {
    PLOG(FATAL) << "failed to set signal mask";
  }
}

static void Initialize(char** argv) {
  android::base::InitLogging(argv);
  android::base::SetAborter([](const char* abort_msg) {
    // If we abort before we get an output fd, contact tombstoned to let any
    // potential listeners know that we failed.
    if (!g_tombstoned_connected) {
      if (!connect_tombstone_server(g_target_thread, &g_tombstoned_socket, &g_output_fd,
                                    &g_proto_fd, kDebuggerdAnyIntercept)) {
        // We failed to connect, not much we can do.
        LOG(ERROR) << "failed to connected to tombstoned to report failure";
        _exit(1);
      }
    }

    dprintf(g_output_fd.get(), "crash_dump failed to dump process");
    if (g_target_thread != 1) {
      dprintf(g_output_fd.get(), " %d: %s\n", g_target_thread, abort_msg);
    } else {
      dprintf(g_output_fd.get(), ": %s\n", abort_msg);
    }

    _exit(1);
  });
}

static void ParseArgs(int argc, char** argv, pid_t* pseudothread_tid, DebuggerdDumpType* dump_type) {
  if (argc != 4) {
    LOG(FATAL) << "wrong number of args: " << argc << " (expected 4)";
  }

  if (!android::base::ParseInt(argv[1], &g_target_thread, 1, std::numeric_limits<pid_t>::max())) {
    LOG(FATAL) << "invalid target tid: " << argv[1];
  }

  if (!android::base::ParseInt(argv[2], pseudothread_tid, 1, std::numeric_limits<pid_t>::max())) {
    LOG(FATAL) << "invalid pseudothread tid: " << argv[2];
  }

  int dump_type_int;
  if (!android::base::ParseInt(argv[3], &dump_type_int, 0)) {
    LOG(FATAL) << "invalid requested dump type: " << argv[3];
  }

  *dump_type = static_cast<DebuggerdDumpType>(dump_type_int);
  switch (*dump_type) {
    case kDebuggerdNativeBacktrace:
    case kDebuggerdTombstone:
    case kDebuggerdTombstoneProto:
      break;

    default:
      LOG(FATAL) << "invalid requested dump type: " << dump_type_int;
  }
}

static void ReadCrashInfo(unique_fd& fd, siginfo_t* siginfo,
                          std::unique_ptr<unwindstack::Regs>* regs, ProcessInfo* process_info,
                          bool* recoverable_crash) {
  std::aligned_storage<sizeof(CrashInfo) + 1, alignof(CrashInfo)>::type buf;
  CrashInfo* crash_info = reinterpret_cast<CrashInfo*>(&buf);
  ssize_t rc = TEMP_FAILURE_RETRY(read(fd.get(), &buf, sizeof(buf)));
  *recoverable_crash = false;
  if (rc == -1) {
    PLOG(FATAL) << "failed to read target ucontext";
  }
  ssize_t expected_size = 0;
  switch (crash_info->header.version) {
    case 1:
    case 2:
    case 3:
      expected_size = sizeof(CrashInfoHeader) + sizeof(CrashInfoDataStatic);
      break;

    case 4:
      expected_size = sizeof(CrashInfoHeader) + sizeof(CrashInfoDataDynamic);
      break;

    default:
      LOG(FATAL) << "unexpected CrashInfo version: " << crash_info->header.version;
      break;
  };

  if (rc < expected_size) {
    LOG(FATAL) << "read " << rc << " bytes when reading target crash information, expected "
                << expected_size;
  }

  switch (crash_info->header.version) {
    case 4:
      process_info->fdsan_table_address = crash_info->data.d.fdsan_table_address;
      process_info->gwp_asan_state = crash_info->data.d.gwp_asan_state;
      process_info->gwp_asan_metadata = crash_info->data.d.gwp_asan_metadata;
      process_info->scudo_stack_depot = crash_info->data.d.scudo_stack_depot;
      process_info->scudo_stack_depot_size = crash_info->data.d.scudo_stack_depot_size;
      process_info->scudo_region_info = crash_info->data.d.scudo_region_info;
      process_info->scudo_ring_buffer = crash_info->data.d.scudo_ring_buffer;
      process_info->scudo_ring_buffer_size = crash_info->data.d.scudo_ring_buffer_size;
      *recoverable_crash = crash_info->data.d.recoverable_crash;
      process_info->crash_detail_page = crash_info->data.d.crash_detail_page;
      FALLTHROUGH_INTENDED;
    case 1:
    case 2:
    case 3:
      process_info->abort_msg_address = crash_info->data.s.abort_msg_address;
      *siginfo = crash_info->data.s.siginfo;
      if (signal_has_si_addr(siginfo)) {
        process_info->has_fault_address = true;
        process_info->maybe_tagged_fault_address = reinterpret_cast<uintptr_t>(siginfo->si_addr);
        process_info->untagged_fault_address =
            untag_address(reinterpret_cast<uintptr_t>(siginfo->si_addr));
      }
      regs->reset(unwindstack::Regs::CreateFromUcontext(unwindstack::Regs::CurrentArch(),
                                                        &crash_info->data.s.ucontext));
      break;

    default:
      __builtin_unreachable();
  }
}

// Wait for a process to clone and return the child's pid.
// Note: this leaves the parent in PTRACE_EVENT_STOP.
static pid_t wait_for_clone(pid_t pid, bool resume_child) {
  int status;
  pid_t result = TEMP_FAILURE_RETRY(waitpid(pid, &status, __WALL));
  if (result == -1) {
    PLOG(FATAL) << "failed to waitpid";
  }

  if (WIFEXITED(status)) {
    LOG(FATAL) << "traced process exited with status " << WEXITSTATUS(status);
  } else if (WIFSIGNALED(status)) {
    LOG(FATAL) << "traced process exited with signal " << WTERMSIG(status);
  } else if (!WIFSTOPPED(status)) {
    LOG(FATAL) << "process didn't stop? (status = " << status << ")";
  }

  if (status >> 8 != (SIGTRAP | (PTRACE_EVENT_CLONE << 8))) {
    LOG(FATAL) << "process didn't stop due to PTRACE_O_TRACECLONE (status = " << status << ")";
  }

  pid_t child;
  if (ptrace(PTRACE_GETEVENTMSG, pid, 0, &child) != 0) {
    PLOG(FATAL) << "failed to get child pid via PTRACE_GETEVENTMSG";
  }

  int stop_signal;
  if (!wait_for_stop(child, &stop_signal)) {
    PLOG(FATAL) << "failed to waitpid on child";
  }

  CHECK_EQ(0, stop_signal);

  if (resume_child) {
    if (ptrace(PTRACE_CONT, child, 0, 0) != 0) {
      PLOG(FATAL) << "failed to resume child (pid = " << child << ")";
    }
  }

  return child;
}

static pid_t wait_for_vm_process(pid_t pseudothread_tid) {
  // The pseudothread will double-fork, we want its grandchild.
  pid_t intermediate = wait_for_clone(pseudothread_tid, true);
  pid_t vm_pid = wait_for_clone(intermediate, false);
  if (ptrace(PTRACE_DETACH, intermediate, 0, 0) != 0) {
    PLOG(FATAL) << "failed to detach from intermediate vm process";
  }

  return vm_pid;
}

static void InstallSigPipeHandler() {
  struct sigaction action = {};
  action.sa_handler = SIG_IGN;
  action.sa_flags = SA_RESTART;
  sigaction(SIGPIPE, &action, nullptr);
}

static bool PtracePeek(int request, pid_t tid, uintptr_t addr, void* data, std::string_view err_msg,
                       uintptr_t* result) {
  errno = 0;
  *result = ptrace(request, tid, addr, data);
  if (errno != 0) {
    PLOG(ERROR) << err_msg;
    return false;
  }
  return true;
}

static bool GetGuestRegistersFromCrashedProcess([[maybe_unused]] pid_t tid,
                                                NativeBridgeGuestRegs* guest_regs) {
  auto process_memory = unwindstack::Memory::CreateProcessMemoryCached(tid);

  uintptr_t header_ptr = 0;
  uintptr_t base = 0;
#if defined(__x86_64__)
  if (!PtracePeek(PTRACE_PEEKUSER, tid, offsetof(user_regs_struct, fs_base), nullptr,
                  "failed to read thread register for thread " + std::to_string(tid), &base)) {
    return false;
  }
#elif defined(__aarch64__)
  // base is implicitly casted to uint64_t.
  struct iovec pt_iov {
    .iov_base = &base, .iov_len = sizeof(base),
  };

  if (ptrace(PTRACE_GETREGSET, tid, NT_ARM_TLS, &pt_iov) != 0) {
    PLOG(ERROR) << "failed to read thread register for thread " << tid;
  }
#else
  // TODO(b/339287219): Add case for Riscv host.
  return false;
#endif
  auto ptr_to_guest_slot = base + TLS_SLOT_NATIVE_BRIDGE_GUEST_STATE * sizeof(uintptr_t);
  if (!process_memory->ReadFully(ptr_to_guest_slot, &header_ptr, sizeof(uintptr_t))) {
    PLOG(ERROR) << "failed to get guest state TLS slot content for thread " << tid;
    return false;
  }

  NativeBridgeGuestStateHeader header;
  if (!process_memory->ReadFully(header_ptr, &header, sizeof(NativeBridgeGuestStateHeader))) {
    PLOG(ERROR) << "failed to get the guest state header for thread " << tid;
    return false;
  }
  if (header.signature != NATIVE_BRIDGE_GUEST_STATE_SIGNATURE) {
    // Return when ptr points to unmapped memory or no valid guest state.
    return false;
  }
  auto guest_state_data_copy = std::make_unique<unsigned char[]>(header.guest_state_data_size);
  if (!process_memory->ReadFully(reinterpret_cast<uintptr_t>(header.guest_state_data),
                                 guest_state_data_copy.get(), header.guest_state_data_size)) {
    PLOG(ERROR) << "failed to read the guest state data for thread " << tid;
    return false;
  }

  LoadGuestStateRegisters(guest_state_data_copy.get(), header.guest_state_data_size, guest_regs);
  return true;
}

static void ReadGuestRegisters([[maybe_unused]] std::unique_ptr<unwindstack::Regs>* regs,
                               pid_t tid) {
  // TODO: remove [[maybe_unused]], when the ARM32 case is removed from the native bridge support.
  NativeBridgeGuestRegs guest_regs;
  if (!GetGuestRegistersFromCrashedProcess(tid, &guest_regs)) {
    return;
  }

  switch (guest_regs.guest_arch) {
#if defined(__LP64__)
    case NATIVE_BRIDGE_ARCH_ARM64: {
      unwindstack::arm64_user_regs arm64_user_regs = {};
      for (size_t i = 0; i < unwindstack::ARM64_REG_R31; i++) {
        arm64_user_regs.regs[i] = guest_regs.regs_arm64.x[i];
      }
      arm64_user_regs.sp = guest_regs.regs_arm64.sp;
      arm64_user_regs.pc = guest_regs.regs_arm64.ip;
      regs->reset(unwindstack::RegsArm64::Read(&arm64_user_regs));

      g_guest_arch = Architecture::ARM64;
      break;
    }
    case NATIVE_BRIDGE_ARCH_RISCV64: {
      unwindstack::riscv64_user_regs riscv64_user_regs = {};
      // RISCV64_REG_PC is at the first position.
      riscv64_user_regs.regs[0] = guest_regs.regs_riscv64.ip;
      for (size_t i = 1; i < unwindstack::RISCV64_REG_REAL_COUNT; i++) {
        riscv64_user_regs.regs[i] = guest_regs.regs_riscv64.x[i];
      }
      regs->reset(unwindstack::RegsRiscv64::Read(&riscv64_user_regs, tid));

      g_guest_arch = Architecture::RISCV64;
      break;
    }
#endif
    default:
      break;
  }
}

int main(int argc, char** argv) {
  DefuseSignalHandlers();
  InstallSigPipeHandler();

  // There appears to be a bug in the kernel where our death causes SIGHUP to
  // be sent to our process group if we exit while it has stopped jobs (e.g.
  // because of wait_for_debugger). Use setsid to create a new process group to
  // avoid hitting this.
  setsid();

  atrace_begin(ATRACE_TAG, "before reparent");
  pid_t target_process = getppid();

  // Open /proc/`getppid()` before we daemonize.
  std::string target_proc_path = "/proc/" + std::to_string(target_process);
  int target_proc_fd = open(target_proc_path.c_str(), O_DIRECTORY | O_RDONLY);
  if (target_proc_fd == -1) {
    PLOG(FATAL) << "failed to open " << target_proc_path;
  }

  // Make sure getppid() hasn't changed.
  if (getppid() != target_process) {
    LOG(FATAL) << "parent died";
  }
  atrace_end(ATRACE_TAG);

  // Reparent ourselves to init, so that the signal handler can waitpid on the
  // original process to avoid leaving a zombie for non-fatal dumps.
  // Move the input/output pipes off of stdout/stderr, out of paranoia.
  unique_fd output_pipe(dup(STDOUT_FILENO));
  unique_fd input_pipe(dup(STDIN_FILENO));

  unique_fd fork_exit_read, fork_exit_write;
  if (!Pipe(&fork_exit_read, &fork_exit_write)) {
    PLOG(FATAL) << "failed to create pipe";
  }

  pid_t forkpid = fork();
  if (forkpid == -1) {
    PLOG(FATAL) << "fork failed";
  } else if (forkpid == 0) {
    fork_exit_read.reset();
  } else {
    // We need the pseudothread to live until we get around to verifying the vm pid against it.
    // The last thing it does is block on a waitpid on us, so wait until our child tells us to die.
    fork_exit_write.reset();
    char buf;
    TEMP_FAILURE_RETRY(read(fork_exit_read.get(), &buf, sizeof(buf)));
    _exit(0);
  }

  ATRACE_NAME("after reparent");
  pid_t pseudothread_tid;
  DebuggerdDumpType dump_type;
  ProcessInfo process_info;

  Initialize(argv);
  ParseArgs(argc, argv, &pseudothread_tid, &dump_type);

  // Die if we take too long.
  //
  // Note: processes with many threads and minidebug-info can take a bit to
  //       unwind, do not make this too small. b/62828735
  alarm(30 * android::base::HwTimeoutMultiplier());

  // Collect the list of open files.
  OpenFilesList open_files;
  {
    ATRACE_NAME("open files");
    populate_open_files_list(&open_files, g_target_thread);
  }

  // In order to reduce the duration that we pause the process for, we ptrace
  // the threads, fetch their registers and associated information, and then
  // fork a separate process as a snapshot of the process's address space.
  std::set<pid_t> threads;
  if (!android::procinfo::GetProcessTids(g_target_thread, &threads)) {
    PLOG(FATAL) << "failed to get process threads";
  }

  std::map<pid_t, ThreadInfo> thread_info;
  siginfo_t siginfo;
  std::string error;
  bool recoverable_crash = false;

  {
    ATRACE_NAME("ptrace");
    for (pid_t thread : threads) {
      // Trace the pseudothread separately, so we can use different options.
      if (thread == pseudothread_tid) {
        continue;
      }

      if (!ptrace_seize_thread(target_proc_fd, thread, &error)) {
        bool fatal = thread == g_target_thread;
        LOG(fatal ? FATAL : WARNING) << error;
      }

      ThreadInfo info;
      info.pid = target_process;
      info.tid = thread;
      info.uid = getuid();
      info.thread_name = get_thread_name(thread);

      unique_fd attr_fd(openat(target_proc_fd, "attr/current", O_RDONLY | O_CLOEXEC));
      if (!android::base::ReadFdToString(attr_fd, &info.selinux_label)) {
        PLOG(WARNING) << "failed to read selinux label";
      }

      if (!ptrace_interrupt(thread, &info.signo)) {
        PLOG(WARNING) << "failed to ptrace interrupt thread " << thread;
        ptrace(PTRACE_DETACH, thread, 0, 0);
        continue;
      }

      struct iovec tagged_addr_iov = {
          &info.tagged_addr_ctrl,
          sizeof(info.tagged_addr_ctrl),
      };
      if (ptrace(PTRACE_GETREGSET, thread, NT_ARM_TAGGED_ADDR_CTRL,
                 reinterpret_cast<void*>(&tagged_addr_iov)) == -1) {
        info.tagged_addr_ctrl = -1;
      }

      struct iovec pac_enabled_keys_iov = {
          &info.pac_enabled_keys,
          sizeof(info.pac_enabled_keys),
      };
      if (ptrace(PTRACE_GETREGSET, thread, NT_ARM_PAC_ENABLED_KEYS,
                 reinterpret_cast<void*>(&pac_enabled_keys_iov)) == -1) {
        info.pac_enabled_keys = -1;
      }

      if (thread == g_target_thread) {
        // Read the thread's registers along with the rest of the crash info out of the pipe.
        ReadCrashInfo(input_pipe, &siginfo, &info.registers, &process_info, &recoverable_crash);
        info.siginfo = &siginfo;
        info.signo = info.siginfo->si_signo;

        info.command_line = get_command_line(g_target_thread);
      } else {
        info.registers.reset(unwindstack::Regs::RemoteGet(thread));
        if (!info.registers) {
          PLOG(WARNING) << "failed to fetch registers for thread " << thread;
          ptrace(PTRACE_DETACH, thread, 0, 0);
          continue;
        }
      }
      ReadGuestRegisters(&info.guest_registers, thread);

      thread_info[thread] = std::move(info);
    }
  }

  // Trace the pseudothread with PTRACE_O_TRACECLONE and tell it to fork.
  if (!ptrace_seize_thread(target_proc_fd, pseudothread_tid, &error, PTRACE_O_TRACECLONE)) {
    LOG(FATAL) << "failed to seize pseudothread: " << error;
  }

  if (TEMP_FAILURE_RETRY(write(output_pipe.get(), "\1", 1)) != 1) {
    PLOG(FATAL) << "failed to write to pseudothread";
  }

  pid_t vm_pid = wait_for_vm_process(pseudothread_tid);
  if (ptrace(PTRACE_DETACH, pseudothread_tid, 0, 0) != 0) {
    PLOG(FATAL) << "failed to detach from pseudothread";
  }

  // The pseudothread can die now.
  fork_exit_write.reset();

  // Defer the message until later, for readability.
  bool wait_for_debugger = android::base::GetBoolProperty(
      "debug.debuggerd.wait_for_debugger",
      android::base::GetBoolProperty("debug.debuggerd.wait_for_gdb", false));
  if (siginfo.si_signo == BIONIC_SIGNAL_DEBUGGER) {
    wait_for_debugger = false;
  }

  // Detach from all of our attached threads before resuming.
  for (const auto& [tid, thread] : thread_info) {
    int resume_signal = thread.signo == BIONIC_SIGNAL_DEBUGGER ? 0 : thread.signo;
    if (wait_for_debugger) {
      resume_signal = 0;
      if (tgkill(target_process, tid, SIGSTOP) != 0) {
        PLOG(WARNING) << "failed to send SIGSTOP to " << tid;
      }
    }

    LOG(DEBUG) << "detaching from thread " << tid;
    if (ptrace(PTRACE_DETACH, tid, 0, resume_signal) != 0) {
      PLOG(ERROR) << "failed to detach from thread " << tid;
    }
  }

  // Drop our capabilities now that we've fetched all of the information we need.
  drop_capabilities();

  {
    ATRACE_NAME("tombstoned_connect");
    LOG(INFO) << "obtaining output fd from tombstoned, type: " << dump_type;
    g_tombstoned_connected = connect_tombstone_server(g_target_thread, &g_tombstoned_socket,
                                                      &g_output_fd, &g_proto_fd, dump_type);
  }

  if (g_tombstoned_connected) {
    if (TEMP_FAILURE_RETRY(dup2(g_output_fd.get(), STDOUT_FILENO)) == -1) {
      PLOG(ERROR) << "failed to dup2 output fd (" << g_output_fd.get() << ") to STDOUT_FILENO";
    }
  } else {
    unique_fd devnull(TEMP_FAILURE_RETRY(open("/dev/null", O_RDWR)));
    TEMP_FAILURE_RETRY(dup2(devnull.get(), STDOUT_FILENO));
    g_output_fd = std::move(devnull);
  }

  LOG(INFO) << "performing dump of process " << target_process
            << " (target tid = " << g_target_thread << ")";

  int signo = siginfo.si_signo;
  bool fatal_signal = signo != BIONIC_SIGNAL_DEBUGGER;
  bool backtrace = false;

  // si_value is special when used with BIONIC_SIGNAL_DEBUGGER.
  //   0: dump tombstone
  //   1: dump backtrace
  if (!fatal_signal) {
    int si_val = siginfo.si_value.sival_int;
    if (si_val == 0) {
      backtrace = false;
    } else if (si_val == 1) {
      backtrace = true;
    } else {
      LOG(WARNING) << "unknown si_value value " << si_val;
    }
  }

  // TODO: Use seccomp to lock ourselves down.

  unwindstack::AndroidRemoteUnwinder unwinder(vm_pid, unwindstack::Regs::CurrentArch());
  unwindstack::ErrorData error_data;
  if (!unwinder.Initialize(error_data)) {
    LOG(FATAL) << "Failed to initialize unwinder object: "
               << unwindstack::GetErrorCodeString(error_data.code);
  }

  std::string amfd_data;
  if (backtrace) {
    ATRACE_NAME("dump_backtrace");
    dump_backtrace(std::move(g_output_fd), &unwinder, thread_info, g_target_thread);
  } else {
    {
      ATRACE_NAME("fdsan table dump");
      populate_fdsan_table(&open_files, unwinder.GetProcessMemory(),
                           process_info.fdsan_table_address);
    }

    {
      ATRACE_NAME("engrave_tombstone");
      unwindstack::ArchEnum regs_arch = unwindstack::ARCH_UNKNOWN;
      switch (g_guest_arch) {
        case Architecture::ARM32: {
          regs_arch = unwindstack::ARCH_ARM;
          break;
        }
        case Architecture::ARM64: {
          regs_arch = unwindstack::ARCH_ARM64;
          break;
        }
        case Architecture::RISCV64: {
          regs_arch = unwindstack::ARCH_RISCV64;
          break;
        }
        default: {
        }
      }
      if (regs_arch == unwindstack::ARCH_UNKNOWN) {
        engrave_tombstone(std::move(g_output_fd), std::move(g_proto_fd), &unwinder, thread_info,
                          g_target_thread, process_info, &open_files, &amfd_data);
      } else {
        unwindstack::AndroidRemoteUnwinder guest_unwinder(vm_pid, regs_arch);
        engrave_tombstone(std::move(g_output_fd), std::move(g_proto_fd), &unwinder, thread_info,
                          g_target_thread, process_info, &open_files, &amfd_data, &g_guest_arch,
                          &guest_unwinder);
      }
    }
  }

  if (fatal_signal) {
    // Don't try to notify ActivityManager if it just crashed, or we might hang until timeout.
    if (thread_info[target_process].thread_name != "system_server") {
      activity_manager_notify(target_process, signo, amfd_data, recoverable_crash);
    }
  }

  if (wait_for_debugger) {
    // Use ALOGI to line up with output from engrave_tombstone.
    ALOGI(
        "***********************************************************\n"
        "* Process %d has been suspended while crashing.\n"
        "* To attach the debugger, run this on the host:\n"
        "*\n"
        "*     lldbclient.py -p %d\n"
        "*\n"
        "***********************************************************",
        target_process, target_process);
  }

  // Close stdout before we notify tombstoned of completion.
  close(STDOUT_FILENO);
  if (g_tombstoned_connected &&
      !notify_completion(g_tombstoned_socket.get(), g_output_fd.get(), g_proto_fd.get())) {
    LOG(ERROR) << "failed to notify tombstoned of completion";
  }

  return 0;
}

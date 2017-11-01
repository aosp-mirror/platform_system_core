/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include "ThreadCapture.h"

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#include <map>
#include <memory>
#include <set>
#include <vector>

#include <android-base/unique_fd.h>

#include "Allocator.h"
#include "log.h"

namespace android {

// bionic interfaces used:
// atoi
// strlcat
// writev

// bionic interfaces reimplemented to avoid allocation:
// getdents64

// Convert a pid > 0 to a string.  sprintf might allocate, so we can't use it.
// Returns a pointer somewhere in buf to a null terminated string, or NULL
// on error.
static char* pid_to_str(char* buf, size_t len, pid_t pid) {
  if (pid <= 0) {
    return nullptr;
  }

  char* ptr = buf + len - 1;
  *ptr = 0;
  while (pid > 0) {
    ptr--;
    if (ptr < buf) {
      return nullptr;
    }
    *ptr = '0' + (pid % 10);
    pid /= 10;
  }

  return ptr;
}

class ThreadCaptureImpl {
 public:
  ThreadCaptureImpl(pid_t pid, Allocator<ThreadCaptureImpl>& allocator);
  ~ThreadCaptureImpl() {}
  bool ListThreads(TidList& tids);
  bool CaptureThreads();
  bool ReleaseThreads();
  bool ReleaseThread(pid_t tid);
  bool CapturedThreadInfo(ThreadInfoList& threads);
  void InjectTestFunc(std::function<void(pid_t)>&& f) { inject_test_func_ = f; }

 private:
  int CaptureThread(pid_t tid);
  bool ReleaseThread(pid_t tid, unsigned int signal);
  int PtraceAttach(pid_t tid);
  void PtraceDetach(pid_t tid, unsigned int signal);
  bool PtraceThreadInfo(pid_t tid, ThreadInfo& thread_info);

  allocator::map<pid_t, unsigned int> captured_threads_;
  Allocator<ThreadCaptureImpl> allocator_;
  pid_t pid_;
  std::function<void(pid_t)> inject_test_func_;
};

ThreadCaptureImpl::ThreadCaptureImpl(pid_t pid, Allocator<ThreadCaptureImpl>& allocator)
    : captured_threads_(allocator), allocator_(allocator), pid_(pid) {}

bool ThreadCaptureImpl::ListThreads(TidList& tids) {
  tids.clear();

  char pid_buf[11];
  char path[256] = "/proc/";
  char* pid_str = pid_to_str(pid_buf, sizeof(pid_buf), pid_);
  if (!pid_str) {
    return false;
  }
  strlcat(path, pid_str, sizeof(path));
  strlcat(path, "/task", sizeof(path));

  android::base::unique_fd fd(open(path, O_CLOEXEC | O_DIRECTORY | O_RDONLY));
  if (fd == -1) {
    MEM_ALOGE("failed to open %s: %s", path, strerror(errno));
    return false;
  }

  struct linux_dirent64 {
    uint64_t d_ino;
    int64_t d_off;
    uint16_t d_reclen;
    char d_type;
    char d_name[];
  } __attribute((packed));
  char dirent_buf[4096];
  ssize_t nread;
  do {
    nread = syscall(SYS_getdents64, fd.get(), dirent_buf, sizeof(dirent_buf));
    if (nread < 0) {
      MEM_ALOGE("failed to get directory entries from %s: %s", path, strerror(errno));
      return false;
    } else if (nread > 0) {
      ssize_t off = 0;
      while (off < nread) {
        linux_dirent64* dirent = reinterpret_cast<linux_dirent64*>(dirent_buf + off);
        off += dirent->d_reclen;
        pid_t tid = atoi(dirent->d_name);
        if (tid <= 0) {
          continue;
        }
        tids.push_back(tid);
      }
    }

  } while (nread != 0);

  return true;
}

bool ThreadCaptureImpl::CaptureThreads() {
  TidList tids{allocator_};

  bool found_new_thread;
  do {
    if (!ListThreads(tids)) {
      ReleaseThreads();
      return false;
    }

    found_new_thread = false;

    for (auto it = tids.begin(); it != tids.end(); it++) {
      auto captured = captured_threads_.find(*it);
      if (captured == captured_threads_.end()) {
        if (CaptureThread(*it) < 0) {
          ReleaseThreads();
          return false;
        }
        found_new_thread = true;
      }
    }
  } while (found_new_thread);

  return true;
}

// Detatches from a thread, delivering signal if nonzero, logs on error
void ThreadCaptureImpl::PtraceDetach(pid_t tid, unsigned int signal) {
  void* sig_ptr = reinterpret_cast<void*>(static_cast<uintptr_t>(signal));
  if (ptrace(PTRACE_DETACH, tid, NULL, sig_ptr) < 0 && errno != ESRCH) {
    MEM_ALOGE("failed to detach from thread %d of process %d: %s", tid, pid_, strerror(errno));
  }
}

// Attaches to and pauses thread.
// Returns 1 on attach, 0 on tid not found, -1 and logs on error
int ThreadCaptureImpl::PtraceAttach(pid_t tid) {
  int ret = ptrace(PTRACE_SEIZE, tid, NULL, NULL);
  if (ret < 0) {
    MEM_ALOGE("failed to attach to thread %d of process %d: %s", tid, pid_, strerror(errno));
    return -1;
  }

  if (inject_test_func_) {
    inject_test_func_(tid);
  }

  if (ptrace(PTRACE_INTERRUPT, tid, 0, 0) < 0) {
    if (errno == ESRCH) {
      return 0;
    } else {
      MEM_ALOGE("failed to interrupt thread %d of process %d: %s", tid, pid_, strerror(errno));
      PtraceDetach(tid, 0);
      return -1;
    }
  }
  return 1;
}

bool ThreadCaptureImpl::PtraceThreadInfo(pid_t tid, ThreadInfo& thread_info) {
  thread_info.tid = tid;

  const unsigned int max_num_regs = 128;  // larger than number of registers on any device
  uintptr_t regs[max_num_regs];
  struct iovec iovec;
  iovec.iov_base = &regs;
  iovec.iov_len = sizeof(regs);

  if (ptrace(PTRACE_GETREGSET, tid, reinterpret_cast<void*>(NT_PRSTATUS), &iovec)) {
    MEM_ALOGE("ptrace getregset for thread %d of process %d failed: %s", tid, pid_, strerror(errno));
    return false;
  }

  unsigned int num_regs = iovec.iov_len / sizeof(uintptr_t);
  thread_info.regs.assign(&regs[0], &regs[num_regs]);

  const int sp =
#if defined(__x86_64__)
      offsetof(struct pt_regs, rsp) / sizeof(uintptr_t)
#elif defined(__i386__)
      offsetof(struct pt_regs, esp) / sizeof(uintptr_t)
#elif defined(__arm__)
      offsetof(struct pt_regs, ARM_sp) / sizeof(uintptr_t)
#elif defined(__aarch64__)
      offsetof(struct user_pt_regs, sp) / sizeof(uintptr_t)
#elif defined(__mips__) || defined(__mips64__)
      offsetof(struct pt_regs, regs[29]) / sizeof(uintptr_t)
#else
#error Unrecognized architecture
#endif
      ;

  // TODO(ccross): use /proc/tid/status or /proc/pid/maps to get start_stack

  thread_info.stack = std::pair<uintptr_t, uintptr_t>(regs[sp], 0);

  return true;
}

int ThreadCaptureImpl::CaptureThread(pid_t tid) {
  int ret = PtraceAttach(tid);
  if (ret <= 0) {
    return ret;
  }

  int status = 0;
  if (TEMP_FAILURE_RETRY(waitpid(tid, &status, __WALL)) < 0) {
    MEM_ALOGE("failed to wait for pause of thread %d of process %d: %s", tid, pid_, strerror(errno));
    PtraceDetach(tid, 0);
    return -1;
  }

  if (!WIFSTOPPED(status)) {
    MEM_ALOGE("thread %d of process %d was not paused after waitpid, killed?", tid, pid_);
    return 0;
  }

  unsigned int resume_signal = 0;

  unsigned int signal = WSTOPSIG(status);
  if ((status >> 16) == PTRACE_EVENT_STOP) {
    switch (signal) {
      case SIGSTOP:
      case SIGTSTP:
      case SIGTTIN:
      case SIGTTOU:
        // group-stop signals
        break;
      case SIGTRAP:
        // normal ptrace interrupt stop
        break;
      default:
        MEM_ALOGE("unexpected signal %d with PTRACE_EVENT_STOP for thread %d of process %d", signal,
                  tid, pid_);
        return -1;
    }
  } else {
    // signal-delivery-stop
    resume_signal = signal;
  }

  captured_threads_[tid] = resume_signal;
  return 1;
}

bool ThreadCaptureImpl::ReleaseThread(pid_t tid) {
  auto it = captured_threads_.find(tid);
  if (it == captured_threads_.end()) {
    return false;
  }
  return ReleaseThread(it->first, it->second);
}

bool ThreadCaptureImpl::ReleaseThread(pid_t tid, unsigned int signal) {
  PtraceDetach(tid, signal);
  return true;
}

bool ThreadCaptureImpl::ReleaseThreads() {
  bool ret = true;
  for (auto it = captured_threads_.begin(); it != captured_threads_.end();) {
    if (ReleaseThread(it->first, it->second)) {
      it = captured_threads_.erase(it);
    } else {
      it++;
      ret = false;
    }
  }
  return ret;
}

bool ThreadCaptureImpl::CapturedThreadInfo(ThreadInfoList& threads) {
  threads.clear();

  for (auto it = captured_threads_.begin(); it != captured_threads_.end(); it++) {
    ThreadInfo t{0, allocator::vector<uintptr_t>(allocator_), std::pair<uintptr_t, uintptr_t>(0, 0)};
    if (!PtraceThreadInfo(it->first, t)) {
      return false;
    }
    threads.push_back(t);
  }
  return true;
}

ThreadCapture::ThreadCapture(pid_t pid, Allocator<ThreadCapture> allocator) {
  Allocator<ThreadCaptureImpl> impl_allocator = allocator;
  impl_ = impl_allocator.make_unique(pid, impl_allocator);
}

ThreadCapture::~ThreadCapture() {}

bool ThreadCapture::ListThreads(TidList& tids) {
  return impl_->ListThreads(tids);
}

bool ThreadCapture::CaptureThreads() {
  return impl_->CaptureThreads();
}

bool ThreadCapture::ReleaseThreads() {
  return impl_->ReleaseThreads();
}

bool ThreadCapture::ReleaseThread(pid_t tid) {
  return impl_->ReleaseThread(tid);
}

bool ThreadCapture::CapturedThreadInfo(ThreadInfoList& threads) {
  return impl_->CapturedThreadInfo(threads);
}

void ThreadCapture::InjectTestFunc(std::function<void(pid_t)>&& f) {
  impl_->InjectTestFunc(std::forward<std::function<void(pid_t)>>(f));
}

}  // namespace android

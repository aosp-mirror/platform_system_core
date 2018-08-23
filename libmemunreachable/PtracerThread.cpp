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

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <sched.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "android-base/macros.h"

#include "PtracerThread.h"
#include "log.h"

namespace android {

class Stack {
 public:
  explicit Stack(size_t size) : size_(size) {
    int prot = PROT_READ | PROT_WRITE;
    int flags = MAP_PRIVATE | MAP_ANONYMOUS;
    page_size_ = sysconf(_SC_PAGE_SIZE);
    size_ += page_size_ * 2;  // guard pages
    base_ = mmap(NULL, size_, prot, flags, -1, 0);
    if (base_ == MAP_FAILED) {
      base_ = NULL;
      size_ = 0;
      return;
    }
    prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, base_, size_, "libmemunreachable stack");
    mprotect(base_, page_size_, PROT_NONE);
    mprotect(top(), page_size_, PROT_NONE);
  };
  ~Stack() { munmap(base_, size_); };
  void* top() {
    return reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(base_) + size_ - page_size_);
  };

 private:
  DISALLOW_COPY_AND_ASSIGN(Stack);

  void* base_;
  size_t size_;
  size_t page_size_;
};

PtracerThread::PtracerThread(const std::function<int()>& func) : child_pid_(0) {
  stack_ = std::make_unique<Stack>(PTHREAD_STACK_MIN);
  if (stack_->top() == nullptr) {
    MEM_LOG_ALWAYS_FATAL("failed to mmap child stack: %s", strerror(errno));
  }

  func_ = std::function<int()>{[&, func]() -> int {
    // In the child thread, lock and unlock the mutex to wait for the parent
    // to finish setting up for the child thread
    std::unique_lock<std::mutex> lk(m_);
    lk.unlock();
    _exit(func());
  }};
}

PtracerThread::~PtracerThread() {
  Kill();
  Join();
  ClearTracer();
  stack_ = nullptr;
}

bool PtracerThread::Start() {
  std::unique_lock<std::mutex> lk(m_);

  // Convert from void(*)(void*) to lambda with captures
  auto proxy = [](void* arg) -> int {
    prctl(PR_SET_NAME, "libmemunreachable ptrace thread");
    return (*reinterpret_cast<std::function<int()>*>(arg))();
  };

  // See README.md for why we create the child process this way
  child_pid_ = clone(proxy, stack_->top(), CLONE_VM | CLONE_FS | CLONE_FILES /*|CLONE_UNTRACED*/,
                     reinterpret_cast<void*>(&func_));
  if (child_pid_ < 0) {
    MEM_ALOGE("failed to clone child: %s", strerror(errno));
    return false;
  }

  SetTracer(child_pid_);

  lk.unlock();

  return true;
}

int PtracerThread::Join() {
  if (child_pid_ == -1) {
    return -1;
  }
  int status;
  int ret = TEMP_FAILURE_RETRY(waitpid(child_pid_, &status, __WALL));
  if (ret < 0) {
    MEM_ALOGE("waitpid %d failed: %s", child_pid_, strerror(errno));
    return -1;
  }

  child_pid_ = -1;

  if (WIFEXITED(status)) {
    return WEXITSTATUS(status);
  } else if (WIFSIGNALED(status)) {
    return -WTERMSIG(status);
  } else {
    MEM_ALOGE("unexpected status %x", status);
    return -1;
  }
}

void PtracerThread::Kill() {
  if (child_pid_ == -1) {
    return;
  }

  syscall(SYS_tkill, child_pid_, SIGKILL);
}

void PtracerThread::SetTracer(pid_t tracer_pid) {
  prctl(PR_SET_PTRACER, tracer_pid);
}

void PtracerThread::ClearTracer() {
  prctl(PR_SET_PTRACER, 0);
}

}  // namespace android

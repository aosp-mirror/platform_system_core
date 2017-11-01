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

#ifndef LIBMEMUNREACHABLE_PTRACER_THREAD_H_
#define LIBMEMUNREACHABLE_PTRACER_THREAD_H_

#include <functional>
#include <mutex>

#include "android-base/macros.h"

#include "Allocator.h"

namespace android {

class Stack;

// PtracerThread is similar to std::thread, except that it creates a "thread"
// that can ptrace the other threads.  The thread is actually a separate
// process, with its own thread group, but shares address space and fds with
// the parent.
class PtracerThread {
 public:
  explicit PtracerThread(const std::function<int()>& func);
  ~PtracerThread();
  bool Start();
  int Join();

 private:
  void SetTracer(pid_t);
  void ClearTracer();
  void Kill();
  DISALLOW_COPY_AND_ASSIGN(PtracerThread);
  std::unique_ptr<Stack> stack_;
  std::function<int()> func_;
  std::mutex m_;
  pid_t child_pid_;
};

}  // namespace android

#endif  // LIBMEMUNREACHABLE_PTRACER_THREAD_H_

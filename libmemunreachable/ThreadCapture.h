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

#ifndef LIBMEMUNREACHABLE_THREAD_CAPTURE_H_
#define LIBMEMUNREACHABLE_THREAD_CAPTURE_H_

#include <utility>

#include "Allocator.h"

namespace android {

struct ThreadInfo {
  pid_t tid;
  allocator::vector<uintptr_t> regs;
  std::pair<uintptr_t, uintptr_t> stack;
};

using TidList = allocator::vector<pid_t>;
using ThreadInfoList = allocator::vector<ThreadInfo>;

class ThreadCaptureImpl;

class ThreadCapture {
 public:
  ThreadCapture(pid_t pid, Allocator<ThreadCapture> allocator);
  ~ThreadCapture();

  bool ListThreads(TidList& tids);
  bool CaptureThreads();
  bool ReleaseThreads();
  bool ReleaseThread(pid_t tid);
  bool CapturedThreadInfo(ThreadInfoList& threads);
  void InjectTestFunc(std::function<void(pid_t)>&& f);

 private:
  ThreadCapture(const ThreadCapture&) = delete;
  void operator=(const ThreadCapture&) = delete;

  Allocator<ThreadCaptureImpl>::unique_ptr impl_;
};

}  // namespace android

#endif

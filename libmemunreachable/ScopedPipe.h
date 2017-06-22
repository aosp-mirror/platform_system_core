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

#ifndef LIBMEMUNREACHABLE_SCOPED_PIPE_H_
#define LIBMEMUNREACHABLE_SCOPED_PIPE_H_

#include <unistd.h>

#include "log.h"

namespace android {

class ScopedPipe {
 public:
  ScopedPipe() : pipefd_{-1, -1} {
    int ret = pipe2(pipefd_, O_CLOEXEC);
    if (ret < 0) {
      MEM_LOG_ALWAYS_FATAL("failed to open pipe");
    }
  }
  ~ScopedPipe() { Close(); }

  ScopedPipe(ScopedPipe&& other) {
    SetReceiver(other.ReleaseReceiver());
    SetSender(other.ReleaseSender());
  }

  ScopedPipe& operator=(ScopedPipe&& other) {
    SetReceiver(other.ReleaseReceiver());
    SetSender(other.ReleaseSender());
    return *this;
  }

  void CloseReceiver() { close(ReleaseReceiver()); }

  void CloseSender() { close(ReleaseSender()); }

  void Close() {
    CloseReceiver();
    CloseSender();
  }

  int Receiver() { return pipefd_[0]; }
  int Sender() { return pipefd_[1]; }

  int ReleaseReceiver() {
    int ret = Receiver();
    SetReceiver(-1);
    return ret;
  }

  int ReleaseSender() {
    int ret = Sender();
    SetSender(-1);
    return ret;
  }

 private:
  void SetReceiver(int fd) { pipefd_[0] = fd; };
  void SetSender(int fd) { pipefd_[1] = fd; };

  int pipefd_[2];
};

}  // namespace android

#endif

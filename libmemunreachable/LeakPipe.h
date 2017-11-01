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

#ifndef LIBMEMUNREACHABLE_LEAK_PIPE_H_
#define LIBMEMUNREACHABLE_LEAK_PIPE_H_

#include <sys/socket.h>

#include <vector>

#include "android-base/macros.h"

#include "ScopedPipe.h"
#include "log.h"

namespace android {

// LeakPipe implements a pipe that can transfer vectors of simple objects
// between processes.  The pipe is created in the sending process and
// transferred over a socketpair that was created before forking.  This ensures
// that only the sending process can have the send side of the pipe open, so if
// the sending process dies the pipe will close.
class LeakPipe {
 public:
  LeakPipe() {
    int ret = socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv_);
    if (ret < 0) {
      MEM_LOG_ALWAYS_FATAL("failed to create socketpair: %s", strerror(errno));
    }
  }

  ~LeakPipe() { Close(); }

  void Close() {
    close(sv_[0]);
    close(sv_[1]);
    sv_[0] = -1;
    sv_[1] = -1;
  }

  bool OpenReceiver() {
    int fd = ReceiveFd(sv_[0]);
    if (fd < 0) {
      return false;
    }

    receiver_.SetFd(fd);
    return true;
  }

  bool OpenSender() {
    ScopedPipe pipe;

    if (!SendFd(sv_[1], pipe.Receiver())) {
      return false;
    }
    pipe.ReleaseReceiver();

    sender_.SetFd(pipe.ReleaseSender());
    return true;
  }

  class LeakPipeBase {
   public:
    LeakPipeBase() : fd_(-1) {}

    ~LeakPipeBase() { Close(); }

    void SetFd(int fd) { fd_ = fd; }

    void Close() {
      close(fd_);
      fd_ = -1;
    }

   protected:
    int fd_;

   private:
    DISALLOW_COPY_AND_ASSIGN(LeakPipeBase);
  };

  class LeakPipeSender : public LeakPipeBase {
   public:
    using LeakPipeBase::LeakPipeBase;

    template <typename T>
    bool Send(const T& value) {
      ssize_t ret = TEMP_FAILURE_RETRY(write(fd_, &value, sizeof(T)));
      if (ret < 0) {
        MEM_ALOGE("failed to send value: %s", strerror(errno));
        return false;
      } else if (static_cast<size_t>(ret) != sizeof(T)) {
        MEM_ALOGE("eof while writing value");
        return false;
      }

      return true;
    }

    template <class T, class Alloc = std::allocator<T>>
    bool SendVector(const std::vector<T, Alloc>& vector) {
      size_t size = vector.size() * sizeof(T);
      if (!Send(size)) {
        return false;
      }

      ssize_t ret = TEMP_FAILURE_RETRY(write(fd_, vector.data(), size));
      if (ret < 0) {
        MEM_ALOGE("failed to send vector: %s", strerror(errno));
        return false;
      } else if (static_cast<size_t>(ret) != size) {
        MEM_ALOGE("eof while writing vector");
        return false;
      }

      return true;
    }
  };

  class LeakPipeReceiver : public LeakPipeBase {
   public:
    using LeakPipeBase::LeakPipeBase;

    template <typename T>
    bool Receive(T* value) {
      ssize_t ret = TEMP_FAILURE_RETRY(read(fd_, reinterpret_cast<void*>(value), sizeof(T)));
      if (ret < 0) {
        MEM_ALOGE("failed to receive value: %s", strerror(errno));
        return false;
      } else if (static_cast<size_t>(ret) != sizeof(T)) {
        MEM_ALOGE("eof while receiving value");
        return false;
      }

      return true;
    }

    template <class T, class Alloc = std::allocator<T>>
    bool ReceiveVector(std::vector<T, Alloc>& vector) {
      size_t size = 0;
      if (!Receive(&size)) {
        return false;
      }

      vector.resize(size / sizeof(T));

      char* ptr = reinterpret_cast<char*>(vector.data());
      while (size > 0) {
        ssize_t ret = TEMP_FAILURE_RETRY(read(fd_, ptr, size));
        if (ret < 0) {
          MEM_ALOGE("failed to send vector: %s", strerror(errno));
          return false;
        } else if (ret == 0) {
          MEM_ALOGE("eof while reading vector");
          return false;
        }
        size -= ret;
        ptr += ret;
      }

      return true;
    }
  };

  LeakPipeReceiver& Receiver() { return receiver_; }

  LeakPipeSender& Sender() { return sender_; }

 private:
  LeakPipeReceiver receiver_;
  LeakPipeSender sender_;
  bool SendFd(int sock, int fd);
  int ReceiveFd(int sock);
  DISALLOW_COPY_AND_ASSIGN(LeakPipe);
  int sv_[2];
};

}  // namespace android

#endif  // LIBMEMUNREACHABLE_LEAK_PIPE_H_

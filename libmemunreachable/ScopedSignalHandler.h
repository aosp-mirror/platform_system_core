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

#ifndef LIBMEMUNREACHABLE_SCOPED_SIGNAL_HANDLER_H_
#define LIBMEMUNREACHABLE_SCOPED_SIGNAL_HANDLER_H_

#include <errno.h>
#include <signal.h>

#include <functional>

#include "android-base/macros.h"

#include "log.h"

namespace android {

class ScopedSignalHandler {
 public:
  using Fn = std::function<void(ScopedSignalHandler&, int, siginfo_t*, void*)>;

  explicit ScopedSignalHandler(Allocator<Fn> allocator) : allocator_(allocator), signal_(-1) {}
  ~ScopedSignalHandler() { reset(); }

  template <class F>
  void install(int signal, F&& f) {
    if (signal_ != -1) MEM_LOG_ALWAYS_FATAL("ScopedSignalHandler already installed");

    handler_ = SignalFn(std::allocator_arg, allocator_,
                        [=](int signal, siginfo_t* si, void* uctx) { f(*this, signal, si, uctx); });

    struct sigaction act {};
    act.sa_sigaction = [](int signal, siginfo_t* si, void* uctx) { handler_(signal, si, uctx); };
    act.sa_flags = SA_SIGINFO;

    int ret = sigaction(signal, &act, &old_act_);
    if (ret < 0) {
      MEM_LOG_ALWAYS_FATAL("failed to install segfault handler: %s", strerror(errno));
    }

    signal_ = signal;
  }

  void reset() {
    if (signal_ != -1) {
      int ret = sigaction(signal_, &old_act_, NULL);
      if (ret < 0) {
        MEM_ALOGE("failed to uninstall segfault handler");
      }
      handler_ = SignalFn{};
      signal_ = -1;
    }
  }

 private:
  using SignalFn = std::function<void(int, siginfo_t*, void*)>;
  DISALLOW_COPY_AND_ASSIGN(ScopedSignalHandler);
  Allocator<Fn> allocator_;
  int signal_;
  struct sigaction old_act_;
  // TODO(ccross): to support multiple ScopedSignalHandlers handler_ would need
  // to be a static map of signals to handlers, but allocated with Allocator.
  static SignalFn handler_;
};

}  // namespace android

#endif  // LIBMEMUNREACHABLE_SCOPED_SIGNAL_HANDLER_H_

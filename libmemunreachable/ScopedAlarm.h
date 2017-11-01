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

#ifndef LIBMEMUNREACHABLE_SCOPED_ALARM_H_
#define LIBMEMUNREACHABLE_SCOPED_ALARM_H_

#include <signal.h>
#include <sys/time.h>

#include <chrono>
#include <functional>

namespace android {

class ScopedAlarm {
 public:
  ScopedAlarm(std::chrono::microseconds us, std::function<void()> func) {
    func_ = func;
    struct sigaction oldact {};
    struct sigaction act {};
    act.sa_handler = [](int) { ScopedAlarm::func_(); };
    sigaction(SIGALRM, &act, &oldact);

    std::chrono::seconds s = std::chrono::duration_cast<std::chrono::seconds>(us);
    itimerval t = itimerval{};
    t.it_value.tv_sec = s.count();
    t.it_value.tv_usec = (us - s).count();
    setitimer(ITIMER_REAL, &t, NULL);
  }
  ~ScopedAlarm() {
    itimerval t = itimerval{};
    setitimer(ITIMER_REAL, &t, NULL);
    struct sigaction act {};
    act.sa_handler = SIG_DFL;
    sigaction(SIGALRM, &act, NULL);
  }

 private:
  static std::function<void()> func_;
};

}  // namespace android

#endif

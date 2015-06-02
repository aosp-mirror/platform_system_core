/*
 * Copyright (C) 2015 The Android Open Source Project
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
#include <signal.h>
#include <stdarg.h>
#include <sys/ptrace.h>

#include <string>

#include "ptrace_fake.h"

siginfo_t g_fake_si = {.si_signo = 0};

void ptrace_set_fake_getsiginfo(const siginfo_t& si) {
  g_fake_si = si;
}

#if !defined(__BIONIC__)
extern "C" long ptrace_fake(enum __ptrace_request request, ...) {
#else
extern "C" long ptrace_fake(int request, ...) {
#endif
  if (request == PTRACE_GETSIGINFO) {
    if (g_fake_si.si_signo == 0) {
      errno = EFAULT;
      return -1;
    }

    va_list ap;
    va_start(ap, request);
    va_arg(ap, int);
    va_arg(ap, int);
    siginfo_t* si = va_arg(ap, siginfo*);
    va_end(ap);
    *si = g_fake_si;
    return 0;
  }
  return -1;
}

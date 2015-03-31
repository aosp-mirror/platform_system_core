/*
 * Copyright (C) 2013 The Android Open Source Project
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
#include <stdint.h>
#include <string.h>
#include <sys/param.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <ucontext.h>
#include <unistd.h>

#include <string>

#include <backtrace/Backtrace.h>
#include <backtrace/BacktraceMap.h>

#include "BacktraceCurrent.h"
#include "BacktraceLog.h"
#include "ThreadEntry.h"
#include "thread_utils.h"

bool BacktraceCurrent::ReadWord(uintptr_t ptr, word_t* out_value) {
  if (!VerifyReadWordArgs(ptr, out_value)) {
    return false;
  }

  backtrace_map_t map;
  FillInMap(ptr, &map);
  if (BacktraceMap::IsValid(map) && map.flags & PROT_READ) {
    *out_value = *reinterpret_cast<word_t*>(ptr);
    return true;
  } else {
    BACK_LOGW("pointer %p not in a readable map", reinterpret_cast<void*>(ptr));
    *out_value = static_cast<word_t>(-1);
    return false;
  }
}

size_t BacktraceCurrent::Read(uintptr_t addr, uint8_t* buffer, size_t bytes) {
  backtrace_map_t map;
  FillInMap(addr, &map);
  if (!BacktraceMap::IsValid(map) || !(map.flags & PROT_READ)) {
    return 0;
  }
  bytes = MIN(map.end - addr, bytes);
  memcpy(buffer, reinterpret_cast<uint8_t*>(addr), bytes);
  return bytes;
}

bool BacktraceCurrent::Unwind(size_t num_ignore_frames, ucontext_t* ucontext) {
  if (ucontext) {
    return UnwindFromContext(num_ignore_frames, ucontext);
  }

  if (Tid() != gettid()) {
    return UnwindThread(num_ignore_frames);
  }

  return UnwindFromContext(num_ignore_frames, nullptr);
}

static pthread_mutex_t g_sigaction_mutex = PTHREAD_MUTEX_INITIALIZER;

static void SignalHandler(int, siginfo_t*, void* sigcontext) {
  ThreadEntry* entry = ThreadEntry::Get(getpid(), gettid(), false);
  if (!entry) {
    BACK_LOGW("Unable to find pid %d tid %d information", getpid(), gettid());
    return;
  }

  entry->CopyUcontextFromSigcontext(sigcontext);

  // Indicate the ucontext is now valid.
  entry->Wake();

  // Pause the thread until the unwind is complete. This avoids having
  // the thread run ahead causing problems.
  // The number indicates that we are waiting for the second Wake() call
  // overall which is made by the thread requesting an unwind.
  entry->Wait(2);

  ThreadEntry::Remove(entry);
}

bool BacktraceCurrent::UnwindThread(size_t num_ignore_frames) {
  // Prevent multiple threads trying to set the trigger action on different
  // threads at the same time.
  pthread_mutex_lock(&g_sigaction_mutex);

  ThreadEntry* entry = ThreadEntry::Get(Pid(), Tid());
  entry->Lock();

  struct sigaction act, oldact;
  memset(&act, 0, sizeof(act));
  act.sa_sigaction = SignalHandler;
  act.sa_flags = SA_RESTART | SA_SIGINFO | SA_ONSTACK;
  sigemptyset(&act.sa_mask);
  if (sigaction(THREAD_SIGNAL, &act, &oldact) != 0) {
    BACK_LOGW("sigaction failed %s", strerror(errno));
    entry->Unlock();
    ThreadEntry::Remove(entry);
    pthread_mutex_unlock(&g_sigaction_mutex);
    return false;
  }

  if (tgkill(Pid(), Tid(), THREAD_SIGNAL) != 0) {
    BACK_LOGW("tgkill %d failed: %s", Tid(), strerror(errno));
    sigaction(THREAD_SIGNAL, &oldact, nullptr);
    entry->Unlock();
    ThreadEntry::Remove(entry);
    pthread_mutex_unlock(&g_sigaction_mutex);
    return false;
  }

  // Wait for the thread to get the ucontext. The number indicates
  // that we are waiting for the first Wake() call made by the thread.
  entry->Wait(1);

  // After the thread has received the signal, allow other unwinders to
  // continue.
  sigaction(THREAD_SIGNAL, &oldact, nullptr);
  pthread_mutex_unlock(&g_sigaction_mutex);

  bool unwind_done = UnwindFromContext(num_ignore_frames, entry->GetUcontext());

  // Tell the signal handler to exit and release the entry.
  entry->Wake();

  return unwind_done;
}

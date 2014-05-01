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

#ifndef _LIBBACKTRACE_BACKTRACE_THREAD_H
#define _LIBBACKTRACE_BACKTRACE_THREAD_H

#include <inttypes.h>
#include <signal.h>
#include <sys/types.h>

#include "BacktraceImpl.h"

enum state_e {
  STATE_WAITING = 0,
  STATE_DUMPING,
  STATE_DONE,
  STATE_CANCEL,
};

// The signal used to cause a thread to dump the stack.
#if defined(__GLIBC__)
// GLIBC reserves __SIGRTMIN signals, so use SIGRTMIN to avoid errors.
#define THREAD_SIGNAL SIGRTMIN
#else
#define THREAD_SIGNAL (__SIGRTMIN+1)
#endif

class BacktraceThreadInterface;

struct ThreadEntry {
  ThreadEntry(
      BacktraceThreadInterface* impl, pid_t pid, pid_t tid,
      size_t num_ignore_frames);
  ~ThreadEntry();

  bool Match(pid_t chk_pid, pid_t chk_tid) { return (chk_pid == pid && chk_tid == tid); }

  static ThreadEntry* AddThreadToUnwind(
      BacktraceThreadInterface* thread_intf, pid_t pid, pid_t tid,
      size_t num_ignored_frames);

  BacktraceThreadInterface* thread_intf;
  pid_t pid;
  pid_t tid;
  ThreadEntry* next;
  ThreadEntry* prev;
  int32_t state;
  int num_ignore_frames;
};

// Interface class that does not contain any local storage, only defines
// virtual functions to be defined by subclasses.
class BacktraceThreadInterface {
public:
  virtual ~BacktraceThreadInterface() { }

  virtual void ThreadUnwind(
      siginfo_t* siginfo, void* sigcontext, size_t num_ignore_frames) = 0;
};

class BacktraceThread : public BacktraceCurrent {
public:
  // impl and thread_intf should point to the same object, this allows
  // the compiler to catch if an implementation does not properly
  // subclass both.
  BacktraceThread(
      BacktraceImpl* impl, BacktraceThreadInterface* thread_intf, pid_t tid,
      BacktraceMap* map);
  virtual ~BacktraceThread();

  virtual bool Unwind(size_t num_ignore_frames);

  virtual void ThreadUnwind(
      siginfo_t* siginfo, void* sigcontext, size_t num_ignore_frames) {
    thread_intf_->ThreadUnwind(siginfo, sigcontext, num_ignore_frames);
  }

private:
  virtual bool TriggerUnwindOnThread(ThreadEntry* entry);

  virtual void FinishUnwind();

  BacktraceThreadInterface* thread_intf_;
};

#endif // _LIBBACKTRACE_BACKTRACE_THREAD_H

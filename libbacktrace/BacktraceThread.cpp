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
#include <inttypes.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>

#include <cutils/atomic.h>
#include <cutils/log.h>

#include "BacktraceThread.h"
#include "thread_utils.h"

//-------------------------------------------------------------------------
// ThreadEntry implementation.
//-------------------------------------------------------------------------
static ThreadEntry* g_list = NULL;
static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;

ThreadEntry::ThreadEntry(
    BacktraceThreadInterface* intf, pid_t pid, pid_t tid, size_t num_ignore_frames)
    : thread_intf_(intf), pid_(pid), tid_(tid), next_(NULL), prev_(NULL),
      state_(STATE_WAITING), num_ignore_frames_(num_ignore_frames) {
}

ThreadEntry::~ThreadEntry() {
  pthread_mutex_lock(&g_mutex);
  if (g_list == this) {
    g_list = next_;
  } else {
    if (next_) {
      next_->prev_ = prev_;
    }
    prev_->next_ = next_;
  }
  pthread_mutex_unlock(&g_mutex);

  next_ = NULL;
  prev_ = NULL;
}

ThreadEntry* ThreadEntry::AddThreadToUnwind(
    BacktraceThreadInterface* intf, pid_t pid, pid_t tid, size_t num_ignore_frames) {
  ThreadEntry* entry = new ThreadEntry(intf, pid, tid, num_ignore_frames);

  pthread_mutex_lock(&g_mutex);
  ThreadEntry* cur_entry = g_list;
  while (cur_entry != NULL) {
    if (cur_entry->Match(pid, tid)) {
      // There is already an entry for this pid/tid, this is bad.
      ALOGW("%s::%s(): Entry for pid %d tid %d already exists.\n",
            __FILE__, __FUNCTION__, pid, tid);

      pthread_mutex_unlock(&g_mutex);
      return NULL;
    }
    cur_entry = cur_entry->next_;
  }

  // Add the entry to the list.
  entry->next_ = g_list;
  if (g_list) {
    g_list->prev_ = entry;
  }
  g_list = entry;
  pthread_mutex_unlock(&g_mutex);

  return entry;
}

//-------------------------------------------------------------------------
// BacktraceThread functions.
//-------------------------------------------------------------------------
static void SignalHandler(int n __attribute__((unused)), siginfo_t* siginfo,
                          void* sigcontext) {
  if (pthread_mutex_lock(&g_mutex) == 0) {
    pid_t pid = getpid();
    pid_t tid = gettid();
    ThreadEntry* cur_entry = g_list;
    while (cur_entry) {
      if (cur_entry->Match(pid, tid)) {
        break;
      }
      cur_entry = cur_entry->next_;
    }
    pthread_mutex_unlock(&g_mutex);
    if (!cur_entry) {
      ALOGW("%s::%s(): Unable to find pid %d tid %d information\n",
            __FILE__, __FUNCTION__, pid, tid);
      return;
    }

    if (android_atomic_acquire_cas(STATE_WAITING, STATE_DUMPING, &cur_entry->state_) == 0) {
      cur_entry->thread_intf_->ThreadUnwind(siginfo, sigcontext,
                                            cur_entry->num_ignore_frames_);
    }
    android_atomic_release_store(STATE_DONE, &cur_entry->state_);
  }
}

BacktraceThread::BacktraceThread(
    BacktraceImpl* impl, BacktraceThreadInterface* thread_intf, pid_t tid)
    : BacktraceCurrent(impl), thread_intf_(thread_intf) {
  backtrace_.tid = tid;
}

BacktraceThread::~BacktraceThread() {
}

void BacktraceThread::FinishUnwind() {
  for (size_t i = 0; i < NumFrames(); i++) {
    backtrace_frame_data_t* frame = &backtrace_.frames[i];

    frame->map_offset = 0;
    uintptr_t map_start;
    frame->map_name = GetMapName(frame->pc, &map_start);
    if (frame->map_name) {
      frame->map_offset = frame->pc - map_start;
    }

    frame->func_offset = 0;
    std::string func_name = GetFunctionName(frame->pc, &frame->func_offset);
    if (!func_name.empty()) {
      frame->func_name = strdup(func_name.c_str());
    }
  }
}

bool BacktraceThread::TriggerUnwindOnThread(ThreadEntry* entry) {
  entry->state_ = STATE_WAITING;

  if (tgkill(Pid(), Tid(), SIGURG) != 0) {
    ALOGW("%s::%s(): tgkill failed %s\n", __FILE__, __FUNCTION__, strerror(errno));
    return false;
  }

  // Allow up to a second for the dump to occur.
  int wait_millis = 1000;
  int32_t state;
  while (true) {
    state = android_atomic_acquire_load(&entry->state_);
    if (state != STATE_WAITING) {
      break;
    }
    if (wait_millis--) {
      usleep(1000);
    } else {
      break;
    }
  }

  bool cancelled = false;
  if (state == STATE_WAITING) {
    if (android_atomic_acquire_cas(state, STATE_CANCEL, &entry->state_) == 0) {
      ALOGW("%s::%s(): Cancelled dump of thread %d\n", __FILE__, __FUNCTION__,
            entry->tid_);
      state = STATE_CANCEL;
      cancelled = true;
    } else {
      state = android_atomic_acquire_load(&entry->state_);
    }
  }

  // Wait for at most one minute for the dump to finish.
  wait_millis = 60000;
  while (android_atomic_acquire_load(&entry->state_) != STATE_DONE) {
    if (wait_millis--) {
      usleep(1000);
    } else {
      ALOGW("%s::%s(): Didn't finish thread unwind in 60 seconds.\n",
            __FILE__, __FUNCTION__);
      break;
    }
  }
  return !cancelled;
}

bool BacktraceThread::Unwind(size_t num_ignore_frames) {
  if (!thread_intf_->Init()) {
    return false;
  }

  ThreadEntry* entry = ThreadEntry::AddThreadToUnwind(
      thread_intf_, Pid(), Tid(), num_ignore_frames);
  if (!entry) {
    return false;
  }

  bool retval = false;
  struct sigaction act, oldact;
  memset(&act, 0, sizeof(act));
  act.sa_sigaction = SignalHandler;
  act.sa_flags = SA_RESTART | SA_SIGINFO | SA_ONSTACK;
  sigemptyset(&act.sa_mask);
  if (sigaction(SIGURG, &act, &oldact) == 0) {
    retval = TriggerUnwindOnThread(entry);
    sigaction(SIGURG, &oldact, NULL);
  } else {
    ALOGW("%s::%s(): sigaction failed %s\n", __FILE__, __FUNCTION__, strerror(errno));
  }

  if (retval) {
    FinishUnwind();
  }
  delete entry;

  return retval;
}

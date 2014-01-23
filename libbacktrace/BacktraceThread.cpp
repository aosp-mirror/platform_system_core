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

#include "BacktraceThread.h"
#include "thread_utils.h"

//-------------------------------------------------------------------------
// ThreadEntry implementation.
//-------------------------------------------------------------------------
static ThreadEntry* g_list = NULL;
static pthread_mutex_t g_entry_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_sigaction_mutex = PTHREAD_MUTEX_INITIALIZER;

ThreadEntry::ThreadEntry(
    BacktraceThreadInterface* intf, pid_t pid, pid_t tid, size_t num_ignore_frames)
    : thread_intf(intf), pid(pid), tid(tid), next(NULL), prev(NULL),
      state(STATE_WAITING), num_ignore_frames(num_ignore_frames) {
}

ThreadEntry::~ThreadEntry() {
  pthread_mutex_lock(&g_entry_mutex);
  if (g_list == this) {
    g_list = next;
  } else {
    if (next) {
      next->prev = prev;
    }
    prev->next = next;
  }
  pthread_mutex_unlock(&g_entry_mutex);

  next = NULL;
  prev = NULL;
}

ThreadEntry* ThreadEntry::AddThreadToUnwind(
    BacktraceThreadInterface* intf, pid_t pid, pid_t tid, size_t num_ignore_frames) {
  ThreadEntry* entry = new ThreadEntry(intf, pid, tid, num_ignore_frames);

  pthread_mutex_lock(&g_entry_mutex);
  ThreadEntry* cur_entry = g_list;
  while (cur_entry != NULL) {
    if (cur_entry->Match(pid, tid)) {
      // There is already an entry for this pid/tid, this is bad.
      BACK_LOGW("Entry for pid %d tid %d already exists.", pid, tid);

      pthread_mutex_unlock(&g_entry_mutex);
      return NULL;
    }
    cur_entry = cur_entry->next;
  }

  // Add the entry to the list.
  entry->next = g_list;
  if (g_list) {
    g_list->prev = entry;
  }
  g_list = entry;
  pthread_mutex_unlock(&g_entry_mutex);

  return entry;
}

//-------------------------------------------------------------------------
// BacktraceThread functions.
//-------------------------------------------------------------------------
static void SignalHandler(int n __attribute__((unused)), siginfo_t* siginfo,
                          void* sigcontext) {
  if (pthread_mutex_lock(&g_entry_mutex) == 0) {
    pid_t pid = getpid();
    pid_t tid = gettid();
    ThreadEntry* cur_entry = g_list;
    while (cur_entry) {
      if (cur_entry->Match(pid, tid)) {
        break;
      }
      cur_entry = cur_entry->next;
    }
    pthread_mutex_unlock(&g_entry_mutex);
    if (!cur_entry) {
      BACK_LOGW("Unable to find pid %d tid %d information", pid, tid);
      return;
    }

    if (android_atomic_acquire_cas(STATE_WAITING, STATE_DUMPING, &cur_entry->state) == 0) {
      cur_entry->thread_intf->ThreadUnwind(siginfo, sigcontext,
                                           cur_entry->num_ignore_frames);
    }
    android_atomic_release_store(STATE_DONE, &cur_entry->state);
  }
}

BacktraceThread::BacktraceThread(
    BacktraceImpl* impl, BacktraceThreadInterface* thread_intf, pid_t tid,
    BacktraceMap* map)
    : BacktraceCurrent(impl, map), thread_intf_(thread_intf) {
  tid_ = tid;
}

BacktraceThread::~BacktraceThread() {
}

void BacktraceThread::FinishUnwind() {
  for (std::vector<backtrace_frame_data_t>::iterator it = frames_.begin();
       it != frames_.end(); ++it) {
    it->map = FindMap(it->pc);

    it->func_offset = 0;
    it->func_name = GetFunctionName(it->pc, &it->func_offset);
  }
}

bool BacktraceThread::TriggerUnwindOnThread(ThreadEntry* entry) {
  entry->state = STATE_WAITING;

  if (tgkill(Pid(), Tid(), SIGURG) != 0) {
    BACK_LOGW("tgkill failed %s", strerror(errno));
    return false;
  }

  // Allow up to ten seconds for the dump to start.
  int wait_millis = 10000;
  int32_t state;
  while (true) {
    state = android_atomic_acquire_load(&entry->state);
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
    if (android_atomic_acquire_cas(state, STATE_CANCEL, &entry->state) == 0) {
      BACK_LOGW("Cancelled dump of thread %d", entry->tid);
      state = STATE_CANCEL;
      cancelled = true;
    } else {
      state = android_atomic_acquire_load(&entry->state);
    }
  }

  // Wait for at most ten seconds for the cancel or dump to finish.
  wait_millis = 10000;
  while (android_atomic_acquire_load(&entry->state) != STATE_DONE) {
    if (wait_millis--) {
      usleep(1000);
    } else {
      BACK_LOGW("Didn't finish thread unwind in 60 seconds.");
      break;
    }
  }
  return !cancelled;
}

bool BacktraceThread::Unwind(size_t num_ignore_frames) {
  ThreadEntry* entry = ThreadEntry::AddThreadToUnwind(
      thread_intf_, Pid(), Tid(), num_ignore_frames);
  if (!entry) {
    return false;
  }

  // Prevent multiple threads trying to set the trigger action on different
  // threads at the same time.
  bool retval = false;
  if (pthread_mutex_lock(&g_sigaction_mutex) == 0) {
    struct sigaction act, oldact;
    memset(&act, 0, sizeof(act));
    act.sa_sigaction = SignalHandler;
    act.sa_flags = SA_RESTART | SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&act.sa_mask);
    if (sigaction(SIGURG, &act, &oldact) == 0) {
      retval = TriggerUnwindOnThread(entry);
      sigaction(SIGURG, &oldact, NULL);
    } else {
      BACK_LOGW("sigaction failed %s", strerror(errno));
    }
    pthread_mutex_unlock(&g_sigaction_mutex);
  } else {
    BACK_LOGW("unable to acquire sigaction mutex.");
  }

  if (retval) {
    FinishUnwind();
  }
  delete entry;

  return retval;
}

/*
** Copyright 2016, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

#include <errno.h>
#include <pthread.h>
#include <time.h>

#include <log/log.h>

#include "log_portability.h"

// Global default if 'last' argument in __android_log_ratelimit is NULL
static time_t g_last_clock;
// Global above can not deal well with callers playing games with the
// seconds argument, so we will also hold on to the maximum value
// ever provided and use that to gain consistency.  If the caller
// provides their own 'last' argument, then they can play such games
// of varying the 'seconds' argument to their pleasure.
static time_t g_last_seconds;
static const time_t last_seconds_default = 10;
static const time_t last_seconds_max = 24 * 60 * 60;  // maximum of a day
static const time_t last_seconds_min = 2;             // granularity
// Lock to protect last_clock and last_seconds, but also 'last'
// argument (not NULL) as supplied to __android_log_ratelimit.
static pthread_mutex_t lock_ratelimit = PTHREAD_MUTEX_INITIALIZER;

// if last is NULL, caller _must_ provide a consistent value for
// seconds, otherwise we will take the maximum ever issued and hold
// on to that.  Preserves value of non-zero errno.  Return -1 if we
// can not acquire a lock, 0 if we are not to log a message, and 1
// if we are ok to log a message.  Caller should check > 0 for true.
LIBLOG_ABI_PUBLIC int __android_log_ratelimit(time_t seconds, time_t* last) {
  int save_errno = errno;

  // Two reasons for trylock failure:
  //   1. In a signal handler. Must prevent deadlock
  //   2. Too many threads calling __android_log_ratelimit.
  //      Bonus to not print if they race here because that
  //      dovetails the goal of ratelimiting. One may print
  //      and the others will wait their turn ...
  if (pthread_mutex_trylock(&lock_ratelimit)) {
    if (save_errno) errno = save_errno;
    return -1;
  }

  if (seconds == 0) {
    seconds = last_seconds_default;
  } else if (seconds < last_seconds_min) {
    seconds = last_seconds_min;
  } else if (seconds > last_seconds_max) {
    seconds = last_seconds_max;
  }

  if (!last) {
    if (g_last_seconds > seconds) {
      seconds = g_last_seconds;
    } else if (g_last_seconds < seconds) {
      g_last_seconds = seconds;
    }
    last = &g_last_clock;
  }

  time_t now = time(NULL);
  if ((now == (time_t)-1) || ((*last + seconds) > now)) {
    pthread_mutex_unlock(&lock_ratelimit);
    if (save_errno) errno = save_errno;
    return 0;
  }
  *last = now;
  pthread_mutex_unlock(&lock_ratelimit);
  if (save_errno) errno = save_errno;
  return 1;
}

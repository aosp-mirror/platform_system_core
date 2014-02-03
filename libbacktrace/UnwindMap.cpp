/*
 * Copyright (C) 2014 The Android Open Source Project
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

#define LOG_TAG "libbacktrace"

#include <pthread.h>
#include <sys/types.h>
#include <unistd.h>

#include <backtrace/BacktraceMap.h>

#include <libunwind.h>

#include "UnwindMap.h"

//-------------------------------------------------------------------------
// libunwind has a single shared address space for the current process
// aka local. If multiple maps are created for the current pid, then
// only update the local address space once, and keep a reference count
// of maps using the same map cursor.
//-------------------------------------------------------------------------
static pthread_mutex_t g_map_mutex = PTHREAD_MUTEX_INITIALIZER;
static unw_map_cursor_t g_map_cursor;
static int g_map_references = 0;

UnwindMap::UnwindMap(pid_t pid) : BacktraceMap(pid) {
  map_cursor_.map_list = NULL;
}

UnwindMap::~UnwindMap() {
  if (pid_ == getpid()) {
    pthread_mutex_lock(&g_map_mutex);
    if (--g_map_references == 0) {
      // Clear the local address space map.
      unw_map_local_set(NULL);
      unw_map_cursor_destroy(&map_cursor_);
    }
    pthread_mutex_unlock(&g_map_mutex);
  } else {
    unw_map_cursor_destroy(&map_cursor_);
  }
}

bool UnwindMap::Build() {
  bool return_value = true;
  if (pid_ == getpid()) {
    pthread_mutex_lock(&g_map_mutex);
    if (g_map_references == 0) {
      return_value = (unw_map_cursor_create(&map_cursor_, pid_) == 0);
      if (return_value) {
        // Set the local address space map to our new map.
        unw_map_local_set(&map_cursor_);
        g_map_references = 1;
        g_map_cursor = map_cursor_;
      }
    } else {
      g_map_references++;
      map_cursor_ = g_map_cursor;
    }
    pthread_mutex_unlock(&g_map_mutex);
  } else {
    return_value = (unw_map_cursor_create(&map_cursor_, pid_) == 0);
  }

  if (!return_value)
    return false;

  // Use the map_cursor information to construct the BacktraceMap data
  // rather than reparsing /proc/self/maps.
  unw_map_cursor_reset(&map_cursor_);
  unw_map_t unw_map;
  while (unw_map_cursor_get(&map_cursor_, &unw_map)) {
    backtrace_map_t map;

    map.start = unw_map.start;
    map.end = unw_map.end;
    map.flags = unw_map.flags;
    map.name = unw_map.path;

    // The maps are in descending order, but we want them in ascending order.
    maps_.push_front(map);
  }

  return true;
}

//-------------------------------------------------------------------------
// BacktraceMap create function.
//-------------------------------------------------------------------------
BacktraceMap* BacktraceMap::Create(pid_t pid) {
  BacktraceMap* map = new UnwindMap(pid);
  if (!map->Build()) {
    delete map;
    return NULL;
  }
  return map;
}

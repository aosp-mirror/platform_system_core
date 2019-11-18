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

#pragma once

#include <stdatomic.h>

#include <cutils/list.h>
#include <log/log.h>

#include "log_portability.h"
#include "uio.h"

__BEGIN_DECLS

/* Union, sock or fd of zero is not allowed unless static initialized */
union android_log_context_union {
  void* priv;
  atomic_int sock;
  atomic_int fd;
};

struct android_log_transport_write {
  const char* name;                  /* human name to describe the transport */
  unsigned logMask;                  /* mask cache of available() success */
  union android_log_context_union context; /* Initialized by static allocation */

  int (*available)(log_id_t logId); /* Does not cause resources to be taken */
  int (*open)();   /* can be called multiple times, reusing current resources */
  void (*close)(); /* free up resources */
  /* write log to transport, returns number of bytes propagated, or -errno */
  int (*write)(log_id_t logId, struct timespec* ts, struct iovec* vec,
               size_t nr);
};

struct android_log_transport_context;

struct android_log_transport_read {
  const char* name; /* human name to describe the transport */

  /* Does not cause resources to be taken */
  int (*available)(log_id_t logId);
  /* Release resources taken by the following interfaces */
  void (*close)(struct logger_list* logger_list, struct android_log_transport_context* transp);
  /*
   * Expect all to instantiate open automagically on any call,
   * so we do not have an explicit open call.
   */
  int (*read)(struct logger_list* logger_list, struct android_log_transport_context* transp,
              struct log_msg* log_msg);
};

struct android_log_transport_context {
  union android_log_context_union context; /* zero init per-transport context */

  struct android_log_transport_read* transport;
};

struct logger_list {
  android_log_transport_context transport_context;
  bool transport_initialized;
  int mode;
  unsigned int tail;
  log_time start;
  pid_t pid;
  uint32_t log_mask;
};

// Format for a 'logger' entry: uintptr_t where only the bottom 32 bits are used.
// bit 31: Set if this 'logger' is for logd.
// bit 30: Set if this 'logger' is for pmsg
// bits 0-2: the decimal value of the log buffer.
// Other bits are unused.

#define LOGGER_LOGD (1 << 31)
#define LOGGER_PMSG (1 << 30)
#define LOGGER_LOG_ID_MASK ((1 << 3) - 1)

inline bool android_logger_is_logd(struct logger* logger) {
  return reinterpret_cast<uintptr_t>(logger) & LOGGER_LOGD;
}

/* OS specific dribs and drabs */

#if defined(_WIN32)
#include <private/android_filesystem_config.h>
typedef uint32_t uid_t;
static inline uid_t __android_log_uid() {
  return AID_SYSTEM;
}
#else
static inline uid_t __android_log_uid() {
  return getuid();
}
#endif

void __android_log_lock();
int __android_log_trylock();
void __android_log_unlock();

__END_DECLS

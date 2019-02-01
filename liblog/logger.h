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
#include <stdbool.h>

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
  struct listnode* node;
  atomic_uintptr_t atomic_pointer;
};

struct android_log_transport_write {
  struct listnode node;
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

struct android_log_logger_list;
struct android_log_transport_context;
struct android_log_logger;

struct android_log_transport_read {
  struct listnode node;
  const char* name; /* human name to describe the transport */

  /* Does not cause resources to be taken */
  int (*available)(log_id_t logId);
  int (*version)(struct android_log_logger* logger,
                 struct android_log_transport_context* transp);
  /* Release resources taken by the following interfaces */
  void (*close)(struct android_log_logger_list* logger_list,
                struct android_log_transport_context* transp);
  /*
   * Expect all to instantiate open automagically on any call,
   * so we do not have an explicit open call.
   */
  int (*read)(struct android_log_logger_list* logger_list,
              struct android_log_transport_context* transp,
              struct log_msg* log_msg);
  /* Must only be called if not ANDROID_LOG_NONBLOCK (blocking) */
  int (*poll)(struct android_log_logger_list* logger_list,
              struct android_log_transport_context* transp);

  int (*clear)(struct android_log_logger* logger,
               struct android_log_transport_context* transp);
  ssize_t (*setSize)(struct android_log_logger* logger,
                     struct android_log_transport_context* transp, size_t size);
  ssize_t (*getSize)(struct android_log_logger* logger,
                     struct android_log_transport_context* transp);
  ssize_t (*getReadableSize)(struct android_log_logger* logger,
                             struct android_log_transport_context* transp);

  ssize_t (*getPrune)(struct android_log_logger_list* logger_list,
                      struct android_log_transport_context* transp, char* buf,
                      size_t len);
  ssize_t (*setPrune)(struct android_log_logger_list* logger_list,
                      struct android_log_transport_context* transp, char* buf,
                      size_t len);
  ssize_t (*getStats)(struct android_log_logger_list* logger_list,
                      struct android_log_transport_context* transp, char* buf,
                      size_t len);
};

struct android_log_logger_list {
  struct listnode logger;
  struct listnode transport;
  int mode;
  unsigned int tail;
  log_time start;
  pid_t pid;
};

struct android_log_logger {
  struct listnode node;
  struct android_log_logger_list* parent;

  log_id_t logId;
};

struct android_log_transport_context {
  struct listnode node;
  union android_log_context_union context; /* zero init per-transport context */
  struct android_log_logger_list* parent;

  struct android_log_transport_read* transport;
  unsigned logMask;      /* mask of requested log buffers */
  int ret;               /* return value associated with following data */
  struct log_msg logMsg; /* peek at upcoming data, valid if logMsg.len != 0 */
};

/* assumes caller has structures read-locked, single threaded, or fenced */
#define transport_context_for_each(transp, logger_list)                          \
  for ((transp) = node_to_item((logger_list)->transport.next,                    \
                               struct android_log_transport_context, node);      \
       ((transp) != node_to_item(&(logger_list)->transport,                      \
                                 struct android_log_transport_context, node)) && \
       ((transp)->parent == (logger_list));                                      \
       (transp) = node_to_item((transp)->node.next,                              \
                               struct android_log_transport_context, node))

#define logger_for_each(logp, logger_list)                          \
  for ((logp) = node_to_item((logger_list)->logger.next,            \
                             struct android_log_logger, node);      \
       ((logp) != node_to_item(&(logger_list)->logger,              \
                               struct android_log_logger, node)) && \
       ((logp)->parent == (logger_list));                           \
       (logp) =                                                     \
           node_to_item((logp)->node.next, struct android_log_logger, node))

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

LIBLOG_HIDDEN void __android_log_lock();
LIBLOG_HIDDEN int __android_log_trylock();
LIBLOG_HIDDEN void __android_log_unlock();

extern LIBLOG_HIDDEN int __android_log_transport;

__END_DECLS

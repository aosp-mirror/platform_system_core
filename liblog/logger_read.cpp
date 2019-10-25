/*
** Copyright 2013-2014, The Android Open Source Project
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

#include "log/log_read.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <android/log.h>
#include <cutils/list.h>
#include <private/android_filesystem_config.h>

#include "log_portability.h"
#include "logger.h"

/* android_logger_alloc unimplemented, no use case */
/* android_logger_free not exported */
static void android_logger_free(struct logger* logger) {
  struct android_log_logger* logger_internal = (struct android_log_logger*)logger;

  if (!logger_internal) {
    return;
  }

  list_remove(&logger_internal->node);

  free(logger_internal);
}

/* android_logger_alloc unimplemented, no use case */

/* method for getting the associated sublog id */
log_id_t android_logger_get_id(struct logger* logger) {
  return ((struct android_log_logger*)logger)->logId;
}

static int init_transport_context(struct android_log_logger_list* logger_list) {
  if (!logger_list) {
    return -EINVAL;
  }

  if (list_empty(&logger_list->logger)) {
    return -EINVAL;
  }

  if (logger_list->transport_initialized) {
    return 0;
  }

#if (FAKE_LOG_DEVICE == 0)
  extern struct android_log_transport_read logdLoggerRead;
  extern struct android_log_transport_read pmsgLoggerRead;

  struct android_log_transport_read* transport;
  transport = (logger_list->mode & ANDROID_LOG_PSTORE) ? &pmsgLoggerRead : &logdLoggerRead;

  struct android_log_logger* logger;
  unsigned logMask = 0;

  logger_for_each(logger, logger_list) {
    log_id_t logId = logger->logId;

    if (logId == LOG_ID_SECURITY && __android_log_uid() != AID_SYSTEM) {
      continue;
    }
    if (transport->read && (!transport->available || transport->available(logId) >= 0)) {
      logMask |= 1 << logId;
    }
  }
  if (!logMask) {
    return -ENODEV;
  }

  logger_list->transport_context.transport = transport;
  logger_list->transport_context.logMask = logMask;
#endif
  return 0;
}

#define LOGGER_FUNCTION(logger, def, func, args...)                                               \
  ssize_t ret = -EINVAL;                                                                          \
  android_log_logger* logger_internal = reinterpret_cast<android_log_logger*>(logger);            \
                                                                                                  \
  if (!logger_internal) {                                                                         \
    return ret;                                                                                   \
  }                                                                                               \
  ret = init_transport_context(logger_internal->parent);                                          \
  if (ret < 0) {                                                                                  \
    return ret;                                                                                   \
  }                                                                                               \
                                                                                                  \
  ret = (def);                                                                                    \
  android_log_transport_context* transport_context = &logger_internal->parent->transport_context; \
  if (transport_context->logMask & (1 << logger_internal->logId) &&                               \
      transport_context->transport && transport_context->transport->func) {                       \
    ssize_t retval =                                                                              \
        (transport_context->transport->func)(logger_internal, transport_context, ##args);         \
    if (ret >= 0 || ret == (def)) {                                                               \
      ret = retval;                                                                               \
    }                                                                                             \
  }                                                                                               \
  return ret

int android_logger_clear(struct logger* logger) {
  LOGGER_FUNCTION(logger, -ENODEV, clear);
}

/* returns the total size of the log's ring buffer */
long android_logger_get_log_size(struct logger* logger) {
  LOGGER_FUNCTION(logger, -ENODEV, getSize);
}

int android_logger_set_log_size(struct logger* logger, unsigned long size) {
  LOGGER_FUNCTION(logger, -ENODEV, setSize, size);
}

/*
 * returns the readable size of the log's ring buffer (that is, amount of the
 * log consumed)
 */
long android_logger_get_log_readable_size(struct logger* logger) {
  LOGGER_FUNCTION(logger, -ENODEV, getReadableSize);
}

/*
 * returns the logger version
 */
int android_logger_get_log_version(struct logger* logger) {
  LOGGER_FUNCTION(logger, 4, version);
}

#define LOGGER_LIST_FUNCTION(logger_list, def, func, args...)                                  \
  android_log_logger_list* logger_list_internal =                                              \
      reinterpret_cast<android_log_logger_list*>(logger_list);                                 \
                                                                                               \
  ssize_t ret = init_transport_context(logger_list_internal);                                  \
  if (ret < 0) {                                                                               \
    return ret;                                                                                \
  }                                                                                            \
                                                                                               \
  ret = (def);                                                                                 \
  android_log_transport_context* transport_context = &logger_list_internal->transport_context; \
  if (transport_context->transport && transport_context->transport->func) {                    \
    ssize_t retval =                                                                           \
        (transport_context->transport->func)(logger_list_internal, transport_context, ##args); \
    if (ret >= 0 || ret == (def)) {                                                            \
      ret = retval;                                                                            \
    }                                                                                          \
  }                                                                                            \
  return ret

/*
 * returns statistics
 */
ssize_t android_logger_get_statistics(struct logger_list* logger_list, char* buf, size_t len) {
  LOGGER_LIST_FUNCTION(logger_list, -ENODEV, getStats, buf, len);
}

ssize_t android_logger_get_prune_list(struct logger_list* logger_list, char* buf, size_t len) {
  LOGGER_LIST_FUNCTION(logger_list, -ENODEV, getPrune, buf, len);
}

int android_logger_set_prune_list(struct logger_list* logger_list, char* buf, size_t len) {
  LOGGER_LIST_FUNCTION(logger_list, -ENODEV, setPrune, buf, len);
}

struct logger_list* android_logger_list_alloc(int mode, unsigned int tail, pid_t pid) {
  struct android_log_logger_list* logger_list;

  logger_list = static_cast<android_log_logger_list*>(calloc(1, sizeof(*logger_list)));
  if (!logger_list) {
    return NULL;
  }

  list_init(&logger_list->logger);
  logger_list->mode = mode;
  logger_list->tail = tail;
  logger_list->pid = pid;

  return (struct logger_list*)logger_list;
}

struct logger_list* android_logger_list_alloc_time(int mode, log_time start, pid_t pid) {
  struct android_log_logger_list* logger_list;

  logger_list = static_cast<android_log_logger_list*>(calloc(1, sizeof(*logger_list)));
  if (!logger_list) {
    return NULL;
  }

  list_init(&logger_list->logger);
  logger_list->mode = mode;
  logger_list->start = start;
  logger_list->pid = pid;

  return (struct logger_list*)logger_list;
}

/* android_logger_list_register unimplemented, no use case */
/* android_logger_list_unregister unimplemented, no use case */

/* Open the named log and add it to the logger list */
struct logger* android_logger_open(struct logger_list* logger_list, log_id_t logId) {
  struct android_log_logger_list* logger_list_internal =
      (struct android_log_logger_list*)logger_list;
  struct android_log_logger* logger;

  if (!logger_list_internal || (logId >= LOG_ID_MAX)) {
    return nullptr;
  }

  logger_for_each(logger, logger_list_internal) {
    if (logger->logId == logId) {
      return reinterpret_cast<struct logger*>(logger);
    }
  }

  logger = static_cast<android_log_logger*>(calloc(1, sizeof(*logger)));
  if (!logger) {
    return nullptr;
  }

  logger->logId = logId;
  list_add_tail(&logger_list_internal->logger, &logger->node);
  logger->parent = logger_list_internal;

  // Reset known transport to re-evaluate, since we added a new logger.
  logger_list_internal->transport_initialized = false;

  return (struct logger*)logger;
}

/* Open the single named log and make it part of a new logger list */
struct logger_list* android_logger_list_open(log_id_t logId, int mode, unsigned int tail,
                                             pid_t pid) {
  struct logger_list* logger_list = android_logger_list_alloc(mode, tail, pid);

  if (!logger_list) {
    return NULL;
  }

  if (!android_logger_open(logger_list, logId)) {
    android_logger_list_free(logger_list);
    return NULL;
  }

  return logger_list;
}

/* Validate log_msg packet, read function has already been null checked */
static int android_transport_read(struct android_log_logger_list* logger_list,
                                  struct android_log_transport_context* transp,
                                  struct log_msg* log_msg) {
  int ret = (*transp->transport->read)(logger_list, transp, log_msg);

  if (ret < 0) {
    return ret;
  }

  if (ret > (int)sizeof(*log_msg)) {
    ret = sizeof(*log_msg);
  }

  if (ret < static_cast<int>(sizeof(log_msg->entry))) {
    return -EINVAL;
  }

  if (log_msg->entry.hdr_size != sizeof(log_msg->entry)) {
    return -EINVAL;
  }

  if (log_msg->entry.len > ret - log_msg->entry.hdr_size) {
    return -EINVAL;
  }

  return ret;
}

/* Read from the selected logs */
int android_logger_list_read(struct logger_list* logger_list, struct log_msg* log_msg) {
  struct android_log_logger_list* logger_list_internal =
      (struct android_log_logger_list*)logger_list;

  int ret = init_transport_context(logger_list_internal);
  if (ret < 0) {
    return ret;
  }

  android_log_transport_context* transport_context = &logger_list_internal->transport_context;
  return android_transport_read(logger_list_internal, transport_context, log_msg);
}

/* Close all the logs */
void android_logger_list_free(struct logger_list* logger_list) {
  struct android_log_logger_list* logger_list_internal =
      (struct android_log_logger_list*)logger_list;

  if (logger_list_internal == NULL) {
    return;
  }

  android_log_transport_context* transport_context = &logger_list_internal->transport_context;

  if (transport_context->transport && transport_context->transport->close) {
    (*transport_context->transport->close)(logger_list_internal, transport_context);
  }

  while (!list_empty(&logger_list_internal->logger)) {
    struct listnode* node = list_head(&logger_list_internal->logger);
    struct android_log_logger* logger = node_to_item(node, struct android_log_logger, node);
    android_logger_free((struct logger*)logger);
  }

  free(logger_list_internal);
}

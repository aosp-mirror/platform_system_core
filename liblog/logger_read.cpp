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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <android/log.h>
#include <cutils/list.h>
#include <private/android_filesystem_config.h>

#include "log_portability.h"
#include "logger.h"

/* method for getting the associated sublog id */
log_id_t android_logger_get_id(struct logger* logger) {
  return static_cast<log_id_t>(reinterpret_cast<uintptr_t>(logger) & LOGGER_LOG_ID_MASK);
}

static struct logger_list* android_logger_list_alloc_internal(int mode, unsigned int tail,
                                                              log_time start, pid_t pid) {
  auto* logger_list = static_cast<struct logger_list*>(calloc(1, sizeof(struct logger_list)));
  if (!logger_list) {
    return nullptr;
  }

  logger_list->mode = mode;
  logger_list->start = start;
  logger_list->tail = tail;
  logger_list->pid = pid;

#if (FAKE_LOG_DEVICE == 0)
  extern struct android_log_transport_read logdLoggerRead;
  extern struct android_log_transport_read pmsgLoggerRead;

  logger_list->transport_context.transport =
      (mode & ANDROID_LOG_PSTORE) ? &pmsgLoggerRead : &logdLoggerRead;
#endif

  return logger_list;
}

struct logger_list* android_logger_list_alloc(int mode, unsigned int tail, pid_t pid) {
  return android_logger_list_alloc_internal(mode, tail, log_time(0, 0), pid);
}

struct logger_list* android_logger_list_alloc_time(int mode, log_time start, pid_t pid) {
  return android_logger_list_alloc_internal(mode, 0, start, pid);
}

/* Open the named log and add it to the logger list */
struct logger* android_logger_open(struct logger_list* logger_list, log_id_t logId) {
  if (!logger_list || (logId >= LOG_ID_MAX)) {
    return nullptr;
  }

  logger_list->log_mask |= 1 << logId;

  uintptr_t logger = logId;
  logger |= (logger_list->mode & ANDROID_LOG_PSTORE) ? LOGGER_PMSG : LOGGER_LOGD;
  return reinterpret_cast<struct logger*>(logger);
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

int android_logger_list_read(struct logger_list* logger_list, struct log_msg* log_msg) {
  if (logger_list == nullptr || logger_list->transport_context.transport == nullptr ||
      logger_list->log_mask == 0) {
    return -EINVAL;
  }

  android_log_transport_context* transp = &logger_list->transport_context;

  int ret = (*transp->transport->read)(logger_list, transp, log_msg);

  if (ret <= 0) {
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

/* Close all the logs */
void android_logger_list_free(struct logger_list* logger_list) {
  if (logger_list == NULL) {
    return;
  }

  android_log_transport_context* transport_context = &logger_list->transport_context;

  if (transport_context->transport && transport_context->transport->close) {
    (*transport_context->transport->close)(logger_list, transport_context);
  }

  free(logger_list);
}

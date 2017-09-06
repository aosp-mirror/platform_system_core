/*
 * Copyright (C) 2017 The Android Open Source Project
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
#include <fcntl.h>
#include <pthread.h>
#if !defined(__MINGW32__)
#include <pwd.h>
#endif
#include <log/uio.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <cutils/list.h> /* template, no library dependency */
#include <log/log_transport.h>
#include <private/android_filesystem_config.h>
#include <private/android_logger.h>
#include <system/thread_defs.h>

#include "config_read.h"
#include "config_write.h"
#include "log_portability.h"
#include "logger.h"

static const char baseServiceName[] = "android.logd";

static int writeToLocalInit();
static int writeToLocalAvailable(log_id_t logId);
static void writeToLocalReset();
static int writeToLocalWrite(log_id_t logId, struct timespec* ts,
                             struct iovec* vec, size_t nr);

LIBLOG_HIDDEN struct android_log_transport_write localLoggerWrite = {
  .node = { &localLoggerWrite.node, &localLoggerWrite.node },
  .context.priv = NULL,
  .name = "local",
  .available = writeToLocalAvailable,
  .open = writeToLocalInit,
  .close = writeToLocalReset,
  .write = writeToLocalWrite,
};

static int writeToLocalVersion(struct android_log_logger* logger,
                               struct android_log_transport_context* transp);
static int writeToLocalRead(struct android_log_logger_list* logger_list,
                            struct android_log_transport_context* transp,
                            struct log_msg* log_msg);
static int writeToLocalPoll(struct android_log_logger_list* logger_list,
                            struct android_log_transport_context* transp);
static void writeToLocalClose(struct android_log_logger_list* logger_list,
                              struct android_log_transport_context* transp);
static int writeToLocalClear(struct android_log_logger* logger,
                             struct android_log_transport_context* transp);
static ssize_t writeToLocalGetSize(struct android_log_logger* logger,
                                   struct android_log_transport_context* transp);
static ssize_t writeToLocalSetSize(
    struct android_log_logger* logger,
    struct android_log_transport_context* transp __unused, size_t size);
static ssize_t writeToLocalGetReadbleSize(
    struct android_log_logger* logger,
    struct android_log_transport_context* transp);

struct android_log_transport_read localLoggerRead = {
  .node = { &localLoggerRead.node, &localLoggerRead.node },
  .name = "local",
  .available = writeToLocalAvailable,
  .version = writeToLocalVersion,
  .read = writeToLocalRead,
  .poll = writeToLocalPoll,
  .close = writeToLocalClose,
  .clear = writeToLocalClear,
  .getSize = writeToLocalGetSize,
  .setSize = writeToLocalSetSize,
  .getReadableSize = writeToLocalGetReadbleSize,
  .getPrune = NULL,
  .setPrune = NULL,
  .getStats = NULL,
};

struct LogBufferElement {
  struct listnode node;
  log_id_t logId;
  pid_t tid;
  log_time timestamp;
  unsigned short len;
  char msg[];
};

static const size_t MAX_SIZE_DEFAULT = 32768;

/*
 * Number of log buffers we support with the following assumption:
 *  . . .
 *   LOG_ID_SECURITY = 5, // security logs go to the system logs only
 *   LOG_ID_KERNEL = 6,   // place last, third-parties can not use it
 *   LOG_ID_MAX
 * } log_id_t;
 *
 * Confirm the following should <log/log_id.h> be adjusted in the future.
 */
#define NUMBER_OF_LOG_BUFFERS \
  ((LOG_ID_SECURITY == (LOG_ID_MAX - 2)) ? LOG_ID_SECURITY : LOG_ID_KERNEL)
#define BLOCK_LOG_BUFFERS(id) \
  (((id) == LOG_ID_SECURITY) || ((id) == LOG_ID_KERNEL))

static struct LogBuffer {
  struct listnode head;
  pthread_rwlock_t listLock;
  char* serviceName; /* Also indicates ready by having a value */
  /* Order and proximity important for memset */
  size_t number[NUMBER_OF_LOG_BUFFERS];         /* clear memset          */
  size_t size[NUMBER_OF_LOG_BUFFERS];           /* clear memset          */
  size_t totalSize[NUMBER_OF_LOG_BUFFERS];      /* init memset           */
  size_t maxSize[NUMBER_OF_LOG_BUFFERS];        /* init MAX_SIZE_DEFAULT */
  struct listnode* last[NUMBER_OF_LOG_BUFFERS]; /* init &head            */
} logbuf = {
  .head = { &logbuf.head, &logbuf.head }, .listLock = PTHREAD_RWLOCK_INITIALIZER,
};

static void LogBufferInit(struct LogBuffer* log) {
  size_t i;

  pthread_rwlock_wrlock(&log->listLock);
  list_init(&log->head);
  memset(log->number, 0,
         sizeof(log->number) + sizeof(log->size) + sizeof(log->totalSize));
  for (i = 0; i < NUMBER_OF_LOG_BUFFERS; ++i) {
    log->maxSize[i] = MAX_SIZE_DEFAULT;
    log->last[i] = &log->head;
  }
#ifdef __BIONIC__
  asprintf(&log->serviceName, "%s@%d:%d", baseServiceName, __android_log_uid(),
           getpid());
#else
  char buffer[sizeof(baseServiceName) + 1 + 5 + 1 + 5 + 8];
  snprintf(buffer, sizeof(buffer), "%s@%d:%d", baseServiceName,
           __android_log_uid(), getpid());
  log->serviceName = strdup(buffer);
#endif
  pthread_rwlock_unlock(&log->listLock);
}

static void LogBufferClear(struct LogBuffer* log) {
  size_t i;
  struct listnode* node;

  pthread_rwlock_wrlock(&log->listLock);
  memset(log->number, 0, sizeof(log->number) + sizeof(log->size));
  for (i = 0; i < NUMBER_OF_LOG_BUFFERS; ++i) {
    log->last[i] = &log->head;
  }
  while ((node = list_head(&log->head)) != &log->head) {
    struct LogBufferElement* element;

    element = node_to_item(node, struct LogBufferElement, node);
    list_remove(node);
    free(element);
  }
  pthread_rwlock_unlock(&log->listLock);
}

static inline void LogBufferFree(struct LogBuffer* log) {
  pthread_rwlock_wrlock(&log->listLock);
  free(log->serviceName);
  log->serviceName = NULL;
  pthread_rwlock_unlock(&log->listLock);
  LogBufferClear(log);
}

static int LogBufferLog(struct LogBuffer* log,
                        struct LogBufferElement* element) {
  log_id_t logId = element->logId;

  pthread_rwlock_wrlock(&log->listLock);
  log->number[logId]++;
  log->size[logId] += element->len;
  log->totalSize[logId] += element->len;
  /* prune entry(s) until enough space is available */
  if (log->last[logId] == &log->head) {
    log->last[logId] = list_tail(&log->head);
  }
  while (log->size[logId] > log->maxSize[logId]) {
    struct listnode* node = log->last[logId];
    struct LogBufferElement* e;
    struct android_log_logger_list* logger_list;

    e = node_to_item(node, struct LogBufferElement, node);
    log->number[logId]--;
    log->size[logId] -= e->len;
    logger_list_rdlock();
    logger_list_for_each(logger_list) {
      struct android_log_transport_context* transp;

      transport_context_for_each(transp, logger_list) {
        if ((transp->transport == &localLoggerRead) &&
            (transp->context.node == node)) {
          if (node == &log->head) {
            transp->context.node = &log->head;
          } else {
            transp->context.node = node->next;
          }
        }
      }
    }
    logger_list_unlock();
    if (node != &log->head) {
      log->last[logId] = node->prev;
    }
    list_remove(node);
    LOG_ALWAYS_FATAL_IF(node == log->last[logId], "corrupted list");
    free(e);
  }
  /* add entry to list */
  list_add_head(&log->head, &element->node);
  /* ToDo: wake up all readers */
  pthread_rwlock_unlock(&log->listLock);

  return element->len;
}

/*
 * return zero if permitted to log directly to logd,
 * return 1 if binder server started and
 * return negative error number if failed to start binder server.
 */
static int writeToLocalInit() {
  pthread_attr_t attr;
  struct LogBuffer* log;

  if (writeToLocalAvailable(LOG_ID_MAIN) < 0) {
    return -EPERM;
  }

  log = &logbuf;
  if (!log->serviceName) {
    LogBufferInit(log);
  }

  if (!log->serviceName) {
    LogBufferFree(log);
    return -ENOMEM;
  }

  return EPERM; /* successful local-only logging */
}

static void writeToLocalReset() {
  LogBufferFree(&logbuf);
}

static int writeToLocalAvailable(log_id_t logId) {
#if !defined(__MINGW32__)
  uid_t uid;
#endif

  if ((logId >= NUMBER_OF_LOG_BUFFERS) || BLOCK_LOG_BUFFERS(logId)) {
    return -EINVAL;
  }

/* Android hard coded permitted, system goes to logd */
#if !defined(__MINGW32__)
  if (__android_log_transport == LOGGER_DEFAULT) {
    uid = __android_log_uid();
    if ((uid < AID_APP) && (getpwuid(uid) != NULL)) {
      return -EPERM;
    }
  }
#endif

  /* ToDo: Ask package manager for LOGD permissions */
  /* Assume we do _not_ have permissions to go to LOGD, so must go local */
  return 0;
}

static int writeToLocalWrite(log_id_t logId, struct timespec* ts,
                             struct iovec* vec, size_t nr) {
  size_t len, i;
  struct LogBufferElement* element;

  if ((logId >= NUMBER_OF_LOG_BUFFERS) || BLOCK_LOG_BUFFERS(logId)) {
    return -EINVAL;
  }

  len = 0;
  for (i = 0; i < nr; ++i) {
    len += vec[i].iov_len;
  }

  if (len > LOGGER_ENTRY_MAX_PAYLOAD) {
    len = LOGGER_ENTRY_MAX_PAYLOAD;
  }
  element = (struct LogBufferElement*)calloc(
      1, sizeof(struct LogBufferElement) + len + 1);
  if (!element) {
    return errno ? -errno : -ENOMEM;
  }
  element->timestamp.tv_sec = ts->tv_sec;
  element->timestamp.tv_nsec = ts->tv_nsec;
#ifdef __BIONIC__
  element->tid = gettid();
#else
  element->tid = getpid();
#endif
  element->logId = logId;
  element->len = len;

  char* cp = element->msg;
  for (i = 0; i < nr; ++i) {
    size_t iov_len = vec[i].iov_len;
    if (iov_len > len) {
      iov_len = len;
    }
    memcpy(cp, vec[i].iov_base, iov_len);
    len -= iov_len;
    if (len == 0) {
      break;
    }
    cp += iov_len;
  }

  return LogBufferLog(&logbuf, element);
}

static int writeToLocalVersion(struct android_log_logger* logger __unused,
                               struct android_log_transport_context* transp
                                   __unused) {
  return 3;
}

/* within reader lock, serviceName already validated */
static struct listnode* writeToLocalNode(
    struct android_log_logger_list* logger_list,
    struct android_log_transport_context* transp) {
  struct listnode* node;
  unsigned logMask;
  unsigned int tail;

  node = transp->context.node;
  if (node) {
    return node;
  }

  if (!logger_list->tail) {
    return transp->context.node = &logbuf.head;
  }

  logMask = transp->logMask;
  tail = logger_list->tail;

  for (node = list_head(&logbuf.head); node != &logbuf.head; node = node->next) {
    struct LogBufferElement* element;
    log_id_t logId;

    element = node_to_item(node, struct LogBufferElement, node);
    logId = element->logId;

    if ((logMask & (1 << logId)) && !--tail) {
      node = node->next;
      break;
    }
  }
  return transp->context.node = node;
}

static int writeToLocalRead(struct android_log_logger_list* logger_list,
                            struct android_log_transport_context* transp,
                            struct log_msg* log_msg) {
  int ret;
  struct listnode* node;
  unsigned logMask;

  pthread_rwlock_rdlock(&logbuf.listLock);
  if (!logbuf.serviceName) {
    pthread_rwlock_unlock(&logbuf.listLock);
    return (logger_list->mode & ANDROID_LOG_NONBLOCK) ? -ENODEV : 0;
  }

  logMask = transp->logMask;

  node = writeToLocalNode(logger_list, transp);

  ret = 0;

  while (node != list_head(&logbuf.head)) {
    struct LogBufferElement* element;
    log_id_t logId;

    node = node->prev;
    element = node_to_item(node, struct LogBufferElement, node);
    logId = element->logId;

    if (logMask & (1 << logId)) {
      ret = log_msg->entry_v3.len = element->len;
      log_msg->entry_v3.hdr_size = sizeof(log_msg->entry_v3);
      log_msg->entry_v3.pid = getpid();
      log_msg->entry_v3.tid = element->tid;
      log_msg->entry_v3.sec = element->timestamp.tv_sec;
      log_msg->entry_v3.nsec = element->timestamp.tv_nsec;
      log_msg->entry_v3.lid = logId;
      memcpy(log_msg->entry_v3.msg, element->msg, ret);
      ret += log_msg->entry_v3.hdr_size;
      break;
    }
  }

  transp->context.node = node;

  /* ToDo: if blocking, and no entry, put reader to sleep */
  pthread_rwlock_unlock(&logbuf.listLock);
  return ret;
}

static int writeToLocalPoll(struct android_log_logger_list* logger_list,
                            struct android_log_transport_context* transp) {
  int ret = (logger_list->mode & ANDROID_LOG_NONBLOCK) ? -ENODEV : 0;

  pthread_rwlock_rdlock(&logbuf.listLock);

  if (logbuf.serviceName) {
    unsigned logMask = transp->logMask;
    struct listnode* node = writeToLocalNode(logger_list, transp);

    ret = (node != list_head(&logbuf.head));
    if (ret) {
      do {
        ret = !!(logMask &
                 (1 << (node_to_item(node->prev, struct LogBufferElement, node))
                           ->logId));
      } while (!ret && ((node = node->prev) != list_head(&logbuf.head)));
    }

    transp->context.node = node;
  }

  pthread_rwlock_unlock(&logbuf.listLock);

  return ret;
}

static void writeToLocalClose(struct android_log_logger_list* logger_list
                                  __unused,
                              struct android_log_transport_context* transp) {
  pthread_rwlock_wrlock(&logbuf.listLock);
  transp->context.node = list_head(&logbuf.head);
  pthread_rwlock_unlock(&logbuf.listLock);
}

static int writeToLocalClear(struct android_log_logger* logger,
                             struct android_log_transport_context* unused
                                 __unused) {
  log_id_t logId = logger->logId;
  struct listnode *node, *n;

  if ((logId >= NUMBER_OF_LOG_BUFFERS) || BLOCK_LOG_BUFFERS(logId)) {
    return -EINVAL;
  }

  pthread_rwlock_wrlock(&logbuf.listLock);
  logbuf.number[logId] = 0;
  logbuf.last[logId] = &logbuf.head;
  list_for_each_safe(node, n, &logbuf.head) {
    struct LogBufferElement* element;
    element = node_to_item(node, struct LogBufferElement, node);

    if (logId == element->logId) {
      struct android_log_logger_list* logger_list;

      logger_list_rdlock();
      logger_list_for_each(logger_list) {
        struct android_log_transport_context* transp;

        transport_context_for_each(transp, logger_list) {
          if ((transp->transport == &localLoggerRead) &&
              (transp->context.node == node)) {
            transp->context.node = node->next;
          }
        }
      }
      logger_list_unlock();
      list_remove(node);
      free(element);
    }
  }

  pthread_rwlock_unlock(&logbuf.listLock);

  return 0;
}

static ssize_t writeToLocalGetSize(struct android_log_logger* logger,
                                   struct android_log_transport_context* transp
                                       __unused) {
  ssize_t ret = -EINVAL;
  log_id_t logId = logger->logId;

  if ((logId < NUMBER_OF_LOG_BUFFERS) && !BLOCK_LOG_BUFFERS(logId)) {
    pthread_rwlock_rdlock(&logbuf.listLock);
    ret = logbuf.maxSize[logId];
    pthread_rwlock_unlock(&logbuf.listLock);
  }

  return ret;
}

static ssize_t writeToLocalSetSize(
    struct android_log_logger* logger,
    struct android_log_transport_context* transp __unused, size_t size) {
  ssize_t ret = -EINVAL;

  if ((size > LOGGER_ENTRY_MAX_LEN) || (size < (4 * 1024 * 1024))) {
    log_id_t logId = logger->logId;
    if ((logId < NUMBER_OF_LOG_BUFFERS) || !BLOCK_LOG_BUFFERS(logId)) {
      pthread_rwlock_wrlock(&logbuf.listLock);
      ret = logbuf.maxSize[logId] = size;
      pthread_rwlock_unlock(&logbuf.listLock);
    }
  }

  return ret;
}

static ssize_t writeToLocalGetReadbleSize(
    struct android_log_logger* logger,
    struct android_log_transport_context* transp __unused) {
  ssize_t ret = -EINVAL;
  log_id_t logId = logger->logId;

  if ((logId < NUMBER_OF_LOG_BUFFERS) && !BLOCK_LOG_BUFFERS(logId)) {
    pthread_rwlock_rdlock(&logbuf.listLock);
    ret = logbuf.serviceName ? (ssize_t)logbuf.size[logId] : -EBADF;
    pthread_rwlock_unlock(&logbuf.listLock);
  }

  return ret;
}

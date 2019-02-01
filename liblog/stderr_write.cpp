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

/*
 * stderr write handler.  Output is logcat-like, and responds to
 * logcat's environment variables ANDROID_PRINTF_LOG and
 * ANDROID_LOG_TAGS to filter output.
 *
 * This transport only provides a writer, that means that it does not
 * provide an End-To-End capability as the logs are effectively _lost_
 * to the stderr file stream.  The purpose of this transport is to
 * supply a means for command line tools to report their logging
 * to the stderr stream, in line with all other activities.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <log/event_tag_map.h>
#include <log/log.h>
#include <log/logprint.h>

#include "log_portability.h"
#include "logger.h"
#include "uio.h"

static int stderrOpen();
static void stderrClose();
static int stderrAvailable(log_id_t logId);
static int stderrWrite(log_id_t logId, struct timespec* ts, struct iovec* vec, size_t nr);

struct stderrContext {
  AndroidLogFormat* logformat;
#if defined(__ANDROID__)
  EventTagMap* eventTagMap;
#endif
};

LIBLOG_HIDDEN struct android_log_transport_write stderrLoggerWrite = {
    .node = {&stderrLoggerWrite.node, &stderrLoggerWrite.node},
    .context.priv = NULL,
    .name = "stderr",
    .available = stderrAvailable,
    .open = stderrOpen,
    .close = stderrClose,
    .write = stderrWrite,
};

static int stderrOpen() {
  struct stderrContext* ctx;
  const char* envStr;
  bool setFormat;

  if (!stderr || (fileno(stderr) < 0)) {
    return -EBADF;
  }

  if (stderrLoggerWrite.context.priv) {
    return fileno(stderr);
  }

  ctx = static_cast<stderrContext*>(calloc(1, sizeof(stderrContext)));
  if (!ctx) {
    return -ENOMEM;
  }

  ctx->logformat = android_log_format_new();
  if (!ctx->logformat) {
    free(ctx);
    return -ENOMEM;
  }

  envStr = getenv("ANDROID_PRINTF_LOG");
  setFormat = false;

  if (envStr) {
    char* formats = strdup(envStr);
    char* sv = NULL;
    char* arg = formats;
    while (!!(arg = strtok_r(arg, ",:; \t\n\r\f", &sv))) {
      AndroidLogPrintFormat format = android_log_formatFromString(arg);
      arg = NULL;
      if (format == FORMAT_OFF) {
        continue;
      }
      if (android_log_setPrintFormat(ctx->logformat, format) <= 0) {
        continue;
      }
      setFormat = true;
    }
    free(formats);
  }
  if (!setFormat) {
    AndroidLogPrintFormat format = android_log_formatFromString("threadtime");
    android_log_setPrintFormat(ctx->logformat, format);
  }
  envStr = getenv("ANDROID_LOG_TAGS");
  if (envStr) {
    android_log_addFilterString(ctx->logformat, envStr);
  }
  stderrLoggerWrite.context.priv = ctx;

  return fileno(stderr);
}

static void stderrClose() {
  stderrContext* ctx = static_cast<stderrContext*>(stderrLoggerWrite.context.priv);

  if (ctx) {
    stderrLoggerWrite.context.priv = NULL;
    if (ctx->logformat) {
      android_log_format_free(ctx->logformat);
      ctx->logformat = NULL;
    }
#if defined(__ANDROID__)
    if (ctx->eventTagMap) {
      android_closeEventTagMap(ctx->eventTagMap);
      ctx->eventTagMap = NULL;
    }
#endif
  }
}

static int stderrAvailable(log_id_t logId) {
  if ((logId >= LOG_ID_MAX) || (logId == LOG_ID_KERNEL)) {
    return -EINVAL;
  }
  return 1;
}

static int stderrWrite(log_id_t logId, struct timespec* ts, struct iovec* vec, size_t nr) {
  struct log_msg log_msg;
  AndroidLogEntry entry;
  char binaryMsgBuf[1024];
  int err;
  size_t i;
  stderrContext* ctx = static_cast<stderrContext*>(stderrLoggerWrite.context.priv);

  if (!ctx) return -EBADF;
  if (!vec || !nr) return -EINVAL;

  log_msg.entry.len = 0;
  log_msg.entry.hdr_size = sizeof(log_msg.entry);
  log_msg.entry.pid = getpid();
#ifdef __BIONIC__
  log_msg.entry.tid = gettid();
#else
  log_msg.entry.tid = getpid();
#endif
  log_msg.entry.sec = ts->tv_sec;
  log_msg.entry.nsec = ts->tv_nsec;
  log_msg.entry.lid = logId;
  log_msg.entry.uid = __android_log_uid();

  for (i = 0; i < nr; ++i) {
    size_t len = vec[i].iov_len;
    if ((log_msg.entry.len + len) > LOGGER_ENTRY_MAX_PAYLOAD) {
      len = LOGGER_ENTRY_MAX_PAYLOAD - log_msg.entry.len;
    }
    if (!len) continue;
    memcpy(log_msg.entry.msg + log_msg.entry.len, vec[i].iov_base, len);
    log_msg.entry.len += len;
  }

  if ((logId == LOG_ID_EVENTS) || (logId == LOG_ID_SECURITY)) {
#if defined(__ANDROID__)
    if (!ctx->eventTagMap) {
      ctx->eventTagMap = android_openEventTagMap(NULL);
    }
#endif
    err = android_log_processBinaryLogBuffer(&log_msg.entry_v1, &entry,
#if defined(__ANDROID__)
                                             ctx->eventTagMap,
#else
                                             NULL,
#endif
                                             binaryMsgBuf, sizeof(binaryMsgBuf));
  } else {
    err = android_log_processLogBuffer(&log_msg.entry_v1, &entry);
  }

  /* print known truncated data, in essence logcat --debug */
  if ((err < 0) && !entry.message) return -EINVAL;

  if (!android_log_shouldPrintLine(ctx->logformat, entry.tag, entry.priority)) {
    return log_msg.entry.len;
  }

  err = android_log_printLogLine(ctx->logformat, fileno(stderr), &entry);
  if (err < 0) return errno ? -errno : -EINVAL;
  return log_msg.entry.len;
}

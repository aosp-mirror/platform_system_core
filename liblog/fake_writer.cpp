/*
 * Copyright (C) 2007-2016 The Android Open Source Project
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
#include <unistd.h>

#include <log/log.h>

#include "config_write.h"
#include "fake_log_device.h"
#include "log_portability.h"
#include "logger.h"

static int fakeOpen();
static void fakeClose();
static int fakeWrite(log_id_t log_id, struct timespec* ts, struct iovec* vec, size_t nr);

static int logFds[(int)LOG_ID_MAX] = {-1, -1, -1, -1, -1, -1};

LIBLOG_HIDDEN struct android_log_transport_write fakeLoggerWrite = {
    .node = {&fakeLoggerWrite.node, &fakeLoggerWrite.node},
    .context.priv = &logFds,
    .name = "fake",
    .available = NULL,
    .open = fakeOpen,
    .close = fakeClose,
    .write = fakeWrite,
};

static int fakeOpen() {
  int i;

  for (i = 0; i < LOG_ID_MAX; i++) {
    /*
     * Known maximum size string, plus an 8 character margin to deal with
     * possible independent changes to android_log_id_to_name().
     */
    char buf[sizeof("/dev/log_security") + 8];
    if (logFds[i] >= 0) {
      continue;
    }
    snprintf(buf, sizeof(buf), "/dev/log_%s", android_log_id_to_name(static_cast<log_id_t>(i)));
    logFds[i] = fakeLogOpen(buf);
    if (logFds[i] < 0) {
      fprintf(stderr, "fakeLogOpen(%s) failed\n", buf);
    }
  }
  return 0;
}

static void fakeClose() {
  int i;

  for (i = 0; i < LOG_ID_MAX; i++) {
    fakeLogClose(logFds[i]);
    logFds[i] = -1;
  }
}

static int fakeWrite(log_id_t log_id, struct timespec*, struct iovec* vec, size_t nr) {
  ssize_t ret;
  size_t i;
  int logFd, len;

  if (/*(int)log_id >= 0 &&*/ (int)log_id >= (int)LOG_ID_MAX) {
    return -EINVAL;
  }

  len = 0;
  for (i = 0; i < nr; ++i) {
    len += vec[i].iov_len;
  }

  if (len > LOGGER_ENTRY_MAX_PAYLOAD) {
    len = LOGGER_ENTRY_MAX_PAYLOAD;
  }

  logFd = logFds[(int)log_id];
  ret = TEMP_FAILURE_RETRY(fakeLogWritev(logFd, vec, nr));
  if (ret < 0) {
    ret = -errno;
  } else if (ret > len) {
    ret = len;
  }

  return ret;
}

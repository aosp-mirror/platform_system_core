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
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#ifdef __BIONIC__
#include <android/set_abort_message.h>
#endif

#include <private/android_filesystem_config.h>
#include <private/android_logger.h>

#include "log_portability.h"
#include "logger.h"
#include "uio.h"

#if (FAKE_LOG_DEVICE == 0)
#include "logd_writer.h"
#include "pmsg_writer.h"
#else
#include "fake_log_device.h"
#endif

#define LOG_BUF_SIZE 1024

#if defined(__ANDROID__)
static int check_log_uid_permissions() {
  uid_t uid = __android_log_uid();

  /* Matches clientHasLogCredentials() in logd */
  if ((uid != AID_SYSTEM) && (uid != AID_ROOT) && (uid != AID_LOG)) {
    uid = geteuid();
    if ((uid != AID_SYSTEM) && (uid != AID_ROOT) && (uid != AID_LOG)) {
      gid_t gid = getgid();
      if ((gid != AID_SYSTEM) && (gid != AID_ROOT) && (gid != AID_LOG)) {
        gid = getegid();
        if ((gid != AID_SYSTEM) && (gid != AID_ROOT) && (gid != AID_LOG)) {
          int num_groups;
          gid_t* groups;

          num_groups = getgroups(0, NULL);
          if (num_groups <= 0) {
            return -EPERM;
          }
          groups = static_cast<gid_t*>(calloc(num_groups, sizeof(gid_t)));
          if (!groups) {
            return -ENOMEM;
          }
          num_groups = getgroups(num_groups, groups);
          while (num_groups > 0) {
            if (groups[num_groups - 1] == AID_LOG) {
              break;
            }
            --num_groups;
          }
          free(groups);
          if (num_groups <= 0) {
            return -EPERM;
          }
        }
      }
    }
  }
  return 0;
}
#endif

/*
 * Release any logger resources. A new log write will immediately re-acquire.
 */
void __android_log_close() {
#if (FAKE_LOG_DEVICE == 0)
  LogdClose();
  PmsgClose();
#else
  FakeClose();
#endif
}

static int write_to_log(log_id_t log_id, struct iovec* vec, size_t nr) {
  int ret, save_errno;
  struct timespec ts;

  save_errno = errno;

  if (log_id == LOG_ID_KERNEL) {
    return -EINVAL;
  }

#if defined(__ANDROID__)
  clock_gettime(android_log_clockid(), &ts);

  if (log_id == LOG_ID_SECURITY) {
    if (vec[0].iov_len < 4) {
      errno = save_errno;
      return -EINVAL;
    }

    ret = check_log_uid_permissions();
    if (ret < 0) {
      errno = save_errno;
      return ret;
    }
    if (!__android_log_security()) {
      /* If only we could reset downstream logd counter */
      errno = save_errno;
      return -EPERM;
    }
  } else if (log_id == LOG_ID_EVENTS || log_id == LOG_ID_STATS) {
    if (vec[0].iov_len < 4) {
      errno = save_errno;
      return -EINVAL;
    }
  } else {
    int prio = *static_cast<int*>(vec[0].iov_base);
    const char* tag = static_cast<const char*>(vec[1].iov_base);
    size_t len = vec[1].iov_len;

    if (!__android_log_is_loggable_len(prio, tag, len - 1, ANDROID_LOG_VERBOSE)) {
      errno = save_errno;
      return -EPERM;
    }
  }
#else
  /* simulate clock_gettime(CLOCK_REALTIME, &ts); */
  {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    ts.tv_sec = tv.tv_sec;
    ts.tv_nsec = tv.tv_usec * 1000;
  }
#endif

  ret = 0;

#if (FAKE_LOG_DEVICE == 0)
  ret = LogdWrite(log_id, &ts, vec, nr);
  PmsgWrite(log_id, &ts, vec, nr);
#else
  ret = FakeWrite(log_id, &ts, vec, nr);
#endif

  errno = save_errno;
  return ret;
}

int __android_log_write(int prio, const char* tag, const char* msg) {
  return __android_log_buf_write(LOG_ID_MAIN, prio, tag, msg);
}

int __android_log_buf_write(int bufID, int prio, const char* tag, const char* msg) {
  if (!tag) tag = "";

#if __BIONIC__
  if (prio == ANDROID_LOG_FATAL) {
    android_set_abort_message(msg);
  }
#endif

  struct iovec vec[3];
  vec[0].iov_base = (unsigned char*)&prio;
  vec[0].iov_len = 1;
  vec[1].iov_base = (void*)tag;
  vec[1].iov_len = strlen(tag) + 1;
  vec[2].iov_base = (void*)msg;
  vec[2].iov_len = strlen(msg) + 1;

  return write_to_log(static_cast<log_id_t>(bufID), vec, 3);
}

int __android_log_vprint(int prio, const char* tag, const char* fmt, va_list ap) {
  char buf[LOG_BUF_SIZE];

  vsnprintf(buf, LOG_BUF_SIZE, fmt, ap);

  return __android_log_write(prio, tag, buf);
}

int __android_log_print(int prio, const char* tag, const char* fmt, ...) {
  va_list ap;
  char buf[LOG_BUF_SIZE];

  va_start(ap, fmt);
  vsnprintf(buf, LOG_BUF_SIZE, fmt, ap);
  va_end(ap);

  return __android_log_write(prio, tag, buf);
}

int __android_log_buf_print(int bufID, int prio, const char* tag, const char* fmt, ...) {
  va_list ap;
  char buf[LOG_BUF_SIZE];

  va_start(ap, fmt);
  vsnprintf(buf, LOG_BUF_SIZE, fmt, ap);
  va_end(ap);

  return __android_log_buf_write(bufID, prio, tag, buf);
}

void __android_log_assert(const char* cond, const char* tag, const char* fmt, ...) {
  char buf[LOG_BUF_SIZE];

  if (fmt) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, LOG_BUF_SIZE, fmt, ap);
    va_end(ap);
  } else {
    /* Msg not provided, log condition.  N.B. Do not use cond directly as
     * format string as it could contain spurious '%' syntax (e.g.
     * "%d" in "blocks%devs == 0").
     */
    if (cond)
      snprintf(buf, LOG_BUF_SIZE, "Assertion failed: %s", cond);
    else
      strcpy(buf, "Unspecified assertion failed");
  }

  // Log assertion failures to stderr for the benefit of "adb shell" users
  // and gtests (http://b/23675822).
  TEMP_FAILURE_RETRY(write(2, buf, strlen(buf)));
  TEMP_FAILURE_RETRY(write(2, "\n", 1));

  __android_log_write(ANDROID_LOG_FATAL, tag, buf);
  abort(); /* abort so we have a chance to debug the situation */
           /* NOTREACHED */
}

int __android_log_bwrite(int32_t tag, const void* payload, size_t len) {
  struct iovec vec[2];

  vec[0].iov_base = &tag;
  vec[0].iov_len = sizeof(tag);
  vec[1].iov_base = (void*)payload;
  vec[1].iov_len = len;

  return write_to_log(LOG_ID_EVENTS, vec, 2);
}

int __android_log_stats_bwrite(int32_t tag, const void* payload, size_t len) {
  struct iovec vec[2];

  vec[0].iov_base = &tag;
  vec[0].iov_len = sizeof(tag);
  vec[1].iov_base = (void*)payload;
  vec[1].iov_len = len;

  return write_to_log(LOG_ID_STATS, vec, 2);
}

int __android_log_security_bwrite(int32_t tag, const void* payload, size_t len) {
  struct iovec vec[2];

  vec[0].iov_base = &tag;
  vec[0].iov_len = sizeof(tag);
  vec[1].iov_base = (void*)payload;
  vec[1].iov_len = len;

  return write_to_log(LOG_ID_SECURITY, vec, 2);
}

/*
 * Like __android_log_bwrite, but takes the type as well.  Doesn't work
 * for the general case where we're generating lists of stuff, but very
 * handy if we just want to dump an integer into the log.
 */
int __android_log_btwrite(int32_t tag, char type, const void* payload, size_t len) {
  struct iovec vec[3];

  vec[0].iov_base = &tag;
  vec[0].iov_len = sizeof(tag);
  vec[1].iov_base = &type;
  vec[1].iov_len = sizeof(type);
  vec[2].iov_base = (void*)payload;
  vec[2].iov_len = len;

  return write_to_log(LOG_ID_EVENTS, vec, 3);
}

/*
 * Like __android_log_bwrite, but used for writing strings to the
 * event log.
 */
int __android_log_bswrite(int32_t tag, const char* payload) {
  struct iovec vec[4];
  char type = EVENT_TYPE_STRING;
  uint32_t len = strlen(payload);

  vec[0].iov_base = &tag;
  vec[0].iov_len = sizeof(tag);
  vec[1].iov_base = &type;
  vec[1].iov_len = sizeof(type);
  vec[2].iov_base = &len;
  vec[2].iov_len = sizeof(len);
  vec[3].iov_base = (void*)payload;
  vec[3].iov_len = len;

  return write_to_log(LOG_ID_EVENTS, vec, 4);
}

/*
 * Like __android_log_security_bwrite, but used for writing strings to the
 * security log.
 */
int __android_log_security_bswrite(int32_t tag, const char* payload) {
  struct iovec vec[4];
  char type = EVENT_TYPE_STRING;
  uint32_t len = strlen(payload);

  vec[0].iov_base = &tag;
  vec[0].iov_len = sizeof(tag);
  vec[1].iov_base = &type;
  vec[1].iov_len = sizeof(type);
  vec[2].iov_base = &len;
  vec[2].iov_len = sizeof(len);
  vec[3].iov_base = (void*)payload;
  vec[3].iov_len = len;

  return write_to_log(LOG_ID_SECURITY, vec, 4);
}

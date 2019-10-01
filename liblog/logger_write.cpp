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

#include <log/event_tag_map.h>
#include <private/android_filesystem_config.h>
#include <private/android_logger.h>

#include "log_portability.h"
#include "logger.h"
#include "uio.h"

#define LOG_BUF_SIZE 1024

android_log_transport_write* android_log_write = nullptr;
android_log_transport_write* android_log_persist_write = nullptr;

static int __write_to_log_init(log_id_t, struct iovec* vec, size_t nr);
static int (*write_to_log)(log_id_t, struct iovec* vec, size_t nr) = __write_to_log_init;

static int check_log_uid_permissions() {
#if defined(__ANDROID__)
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
#endif
  return 0;
}

static void __android_log_cache_available(struct android_log_transport_write* node) {
  uint32_t i;

  if (node->logMask) {
    return;
  }

  for (i = LOG_ID_MIN; i < LOG_ID_MAX; ++i) {
    if (node->write && (i != LOG_ID_KERNEL) &&
        ((i != LOG_ID_SECURITY) || (check_log_uid_permissions() == 0)) &&
        (!node->available || ((*node->available)(static_cast<log_id_t>(i)) >= 0))) {
      node->logMask |= 1 << i;
    }
  }
}

#if defined(__ANDROID__)
static atomic_uintptr_t tagMap;
#endif

/*
 * Release any logger resources. A new log write will immediately re-acquire.
 */
void __android_log_close() {
#if defined(__ANDROID__)
  EventTagMap* m;
#endif

  __android_log_lock();

  write_to_log = __write_to_log_init;

  /*
   * Threads that are actively writing at this point are not held back
   * by a lock and are at risk of dropping the messages with a return code
   * -EBADF. Prefer to return error code than add the overhead of a lock to
   * each log writing call to guarantee delivery. In addition, anyone
   * calling this is doing so to release the logging resources and shut down,
   * for them to do so with outstanding log requests in other threads is a
   * disengenuous use of this function.
   */

  if (android_log_write != nullptr) {
    android_log_write->close();
  }

  if (android_log_persist_write != nullptr) {
    android_log_persist_write->close();
  }

  android_log_write = nullptr;
  android_log_persist_write = nullptr;

#if defined(__ANDROID__)
  /*
   * Additional risk here somewhat mitigated by immediately unlock flushing
   * the processor cache. The multi-threaded race that we choose to accept,
   * to minimize locking, is an atomic_load in a writer picking up a value
   * just prior to entering this routine. There will be an use after free.
   *
   * Again, anyone calling this is doing so to release the logging resources
   * is most probably going to quiesce then shut down; or to restart after
   * a fork so the risk should be non-existent. For this reason we
   * choose a mitigation stance for efficiency instead of incuring the cost
   * of a lock for every log write.
   */
  m = (EventTagMap*)atomic_exchange(&tagMap, (uintptr_t)0);
#endif

  __android_log_unlock();

#if defined(__ANDROID__)
  if (m != (EventTagMap*)(uintptr_t)-1LL) android_closeEventTagMap(m);
#endif
}

static bool transport_initialize(android_log_transport_write* transport) {
  if (transport == nullptr) {
    return false;
  }

  __android_log_cache_available(transport);
  if (!transport->logMask) {
    return false;
  }

  // TODO: Do we actually need to call close() if open() fails?
  if (transport->open() < 0) {
    transport->close();
    return false;
  }

  return true;
}

/* log_init_lock assumed */
static int __write_to_log_initialize() {
#if (FAKE_LOG_DEVICE == 0)
  extern struct android_log_transport_write logdLoggerWrite;
  extern struct android_log_transport_write pmsgLoggerWrite;

  android_log_write = &logdLoggerWrite;
  android_log_persist_write = &pmsgLoggerWrite;
#else
  extern struct android_log_transport_write fakeLoggerWrite;

  android_log_write = &fakeLoggerWrite;
#endif

  if (!transport_initialize(android_log_write)) {
    android_log_write = nullptr;
    return -ENODEV;
  }

  if (!transport_initialize(android_log_persist_write)) {
    android_log_persist_write = nullptr;
  }

  return 1;
}

static int __write_to_log_daemon(log_id_t log_id, struct iovec* vec, size_t nr) {
  int ret, save_errno;
  struct timespec ts;
  size_t len, i;

  for (len = i = 0; i < nr; ++i) {
    len += vec[i].iov_len;
  }
  if (!len) {
    return -EINVAL;
  }

  save_errno = errno;
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
    const char* tag;
    size_t len;
    EventTagMap *m, *f;

    if (vec[0].iov_len < 4) {
      errno = save_errno;
      return -EINVAL;
    }

    tag = NULL;
    len = 0;
    f = NULL;
    m = (EventTagMap*)atomic_load(&tagMap);

    if (!m) {
      ret = __android_log_trylock();
      m = (EventTagMap*)atomic_load(&tagMap); /* trylock flush cache */
      if (!m) {
        m = android_openEventTagMap(NULL);
        if (ret) { /* trylock failed, use local copy, mark for close */
          f = m;
        } else {
          if (!m) { /* One chance to open map file */
            m = (EventTagMap*)(uintptr_t)-1LL;
          }
          atomic_store(&tagMap, (uintptr_t)m);
        }
      }
      if (!ret) { /* trylock succeeded, unlock */
        __android_log_unlock();
      }
    }
    if (m && (m != (EventTagMap*)(uintptr_t)-1LL)) {
      tag = android_lookupEventTag_len(m, &len, *static_cast<uint32_t*>(vec[0].iov_base));
    }
    ret = __android_log_is_loggable_len(ANDROID_LOG_INFO, tag, len, ANDROID_LOG_VERBOSE);
    if (f) { /* local copy marked for close */
      android_closeEventTagMap(f);
    }
    if (!ret) {
      errno = save_errno;
      return -EPERM;
    }
  } else {
    /* Validate the incoming tag, tag content can not split across iovec */
    char prio = ANDROID_LOG_VERBOSE;
    const char* tag = static_cast<const char*>(vec[0].iov_base);
    size_t len = vec[0].iov_len;
    if (!tag) {
      len = 0;
    }
    if (len > 0) {
      prio = *tag;
      if (len > 1) {
        --len;
        ++tag;
      } else {
        len = vec[1].iov_len;
        tag = ((const char*)vec[1].iov_base);
        if (!tag) {
          len = 0;
        }
      }
    }
    /* tag must be nul terminated */
    if (tag && strnlen(tag, len) >= len) {
      tag = NULL;
    }

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
  i = 1 << log_id;

  if (android_log_write != nullptr && (android_log_write->logMask & i)) {
    ssize_t retval;
    retval = android_log_write->write(log_id, &ts, vec, nr);
    if (ret >= 0) {
      ret = retval;
    }
  }

  if (android_log_persist_write != nullptr && (android_log_persist_write->logMask & i)) {
    android_log_persist_write->write(log_id, &ts, vec, nr);
  }

  errno = save_errno;
  return ret;
}

static int __write_to_log_init(log_id_t log_id, struct iovec* vec, size_t nr) {
  int ret, save_errno = errno;

  __android_log_lock();

  if (write_to_log == __write_to_log_init) {
    ret = __write_to_log_initialize();
    if (ret < 0) {
      __android_log_unlock();
      errno = save_errno;
      return ret;
    }

    write_to_log = __write_to_log_daemon;
  }

  __android_log_unlock();

  ret = write_to_log(log_id, vec, nr);
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

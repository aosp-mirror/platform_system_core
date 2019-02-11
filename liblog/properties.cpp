/*
** Copyright 2014, The Android Open Source Project
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

#include <log/log_properties.h>

#include <ctype.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#define _REALLY_INCLUDE_SYS__SYSTEM_PROPERTIES_H_
#include <sys/_system_properties.h>
#include <unistd.h>

#include <private/android_logger.h>

#include "log_portability.h"

static pthread_mutex_t lock_loggable = PTHREAD_MUTEX_INITIALIZER;

static int lock() {
  /*
   * If we trigger a signal handler in the middle of locked activity and the
   * signal handler logs a message, we could get into a deadlock state.
   */
  /*
   *  Any contention, and we can turn around and use the non-cached method
   * in less time than the system call associated with a mutex to deal with
   * the contention.
   */
  return pthread_mutex_trylock(&lock_loggable);
}

static void unlock() {
  pthread_mutex_unlock(&lock_loggable);
}

struct cache {
  const prop_info* pinfo;
  uint32_t serial;
};

struct cache_char {
  struct cache cache;
  unsigned char c;
};

static int check_cache(struct cache* cache) {
  return cache->pinfo && __system_property_serial(cache->pinfo) != cache->serial;
}

#define BOOLEAN_TRUE 0xFF
#define BOOLEAN_FALSE 0xFE

static void refresh_cache(struct cache_char* cache, const char* key) {
  char buf[PROP_VALUE_MAX];

  if (!cache->cache.pinfo) {
    cache->cache.pinfo = __system_property_find(key);
    if (!cache->cache.pinfo) {
      return;
    }
  }
  cache->cache.serial = __system_property_serial(cache->cache.pinfo);
  __system_property_read(cache->cache.pinfo, 0, buf);
  switch (buf[0]) {
    case 't':
    case 'T':
      cache->c = strcasecmp(buf + 1, "rue") ? buf[0] : BOOLEAN_TRUE;
      break;
    case 'f':
    case 'F':
      cache->c = strcasecmp(buf + 1, "alse") ? buf[0] : BOOLEAN_FALSE;
      break;
    default:
      cache->c = buf[0];
  }
}

static int __android_log_level(const char* tag, size_t len, int default_prio) {
  /* sizeof() is used on this array below */
  static const char log_namespace[] = "persist.log.tag.";
  static const size_t base_offset = 8; /* skip "persist." */
  /* calculate the size of our key temporary buffer */
  const size_t taglen = tag ? len : 0;
  /* sizeof(log_namespace) = strlen(log_namespace) + 1 */
  char key[sizeof(log_namespace) + taglen];
  char* kp;
  size_t i;
  char c = 0;
  /*
   * Single layer cache of four properties. Priorities are:
   *    log.tag.<tag>
   *    persist.log.tag.<tag>
   *    log.tag
   *    persist.log.tag
   * Where the missing tag matches all tags and becomes the
   * system global default. We do not support ro.log.tag* .
   */
  static char* last_tag;
  static size_t last_tag_len;
  static uint32_t global_serial;
  /* some compilers erroneously see uninitialized use. !not_locked */
  uint32_t current_global_serial = 0;
  static struct cache_char tag_cache[2];
  static struct cache_char global_cache[2];
  int change_detected;
  int global_change_detected;
  int not_locked;

  strcpy(key, log_namespace);

  global_change_detected = change_detected = not_locked = lock();

  if (!not_locked) {
    /*
     *  check all known serial numbers to changes.
     */
    for (i = 0; i < (sizeof(tag_cache) / sizeof(tag_cache[0])); ++i) {
      if (check_cache(&tag_cache[i].cache)) {
        change_detected = 1;
      }
    }
    for (i = 0; i < (sizeof(global_cache) / sizeof(global_cache[0])); ++i) {
      if (check_cache(&global_cache[i].cache)) {
        global_change_detected = 1;
      }
    }

    current_global_serial = __system_property_area_serial();
    if (current_global_serial != global_serial) {
      change_detected = 1;
      global_change_detected = 1;
    }
  }

  if (taglen) {
    int local_change_detected = change_detected;
    if (!not_locked) {
      if (!last_tag || !last_tag[0] || (last_tag[0] != tag[0]) ||
          strncmp(last_tag + 1, tag + 1, last_tag_len - 1)) {
        /* invalidate log.tag.<tag> cache */
        for (i = 0; i < (sizeof(tag_cache) / sizeof(tag_cache[0])); ++i) {
          tag_cache[i].cache.pinfo = NULL;
          tag_cache[i].c = '\0';
        }
        if (last_tag) last_tag[0] = '\0';
        local_change_detected = 1;
      }
      if (!last_tag || !last_tag[0]) {
        if (!last_tag) {
          last_tag = static_cast<char*>(calloc(1, len + 1));
          last_tag_len = 0;
          if (last_tag) last_tag_len = len + 1;
        } else if (len >= last_tag_len) {
          last_tag = static_cast<char*>(realloc(last_tag, len + 1));
          last_tag_len = 0;
          if (last_tag) last_tag_len = len + 1;
        }
        if (last_tag) {
          strncpy(last_tag, tag, len);
          last_tag[len] = '\0';
        }
      }
    }
    strncpy(key + sizeof(log_namespace) - 1, tag, len);
    key[sizeof(log_namespace) - 1 + len] = '\0';

    kp = key;
    for (i = 0; i < (sizeof(tag_cache) / sizeof(tag_cache[0])); ++i) {
      struct cache_char* cache = &tag_cache[i];
      struct cache_char temp_cache;

      if (not_locked) {
        temp_cache.cache.pinfo = NULL;
        temp_cache.c = '\0';
        cache = &temp_cache;
      }
      if (local_change_detected) {
        refresh_cache(cache, kp);
      }

      if (cache->c) {
        c = cache->c;
        break;
      }

      kp = key + base_offset;
    }
  }

  switch (toupper(c)) { /* if invalid, resort to global */
    case 'V':
    case 'D':
    case 'I':
    case 'W':
    case 'E':
    case 'F': /* Not officially supported */
    case 'A':
    case 'S':
    case BOOLEAN_FALSE: /* Not officially supported */
      break;
    default:
      /* clear '.' after log.tag */
      key[sizeof(log_namespace) - 2] = '\0';

      kp = key;
      for (i = 0; i < (sizeof(global_cache) / sizeof(global_cache[0])); ++i) {
        struct cache_char* cache = &global_cache[i];
        struct cache_char temp_cache;

        if (not_locked) {
          temp_cache = *cache;
          if (temp_cache.cache.pinfo != cache->cache.pinfo) { /* check atomic */
            temp_cache.cache.pinfo = NULL;
            temp_cache.c = '\0';
          }
          cache = &temp_cache;
        }
        if (global_change_detected) {
          refresh_cache(cache, kp);
        }

        if (cache->c) {
          c = cache->c;
          break;
        }

        kp = key + base_offset;
      }
      break;
  }

  if (!not_locked) {
    global_serial = current_global_serial;
    unlock();
  }

  switch (toupper(c)) {
    /* clang-format off */
    case 'V': return ANDROID_LOG_VERBOSE;
    case 'D': return ANDROID_LOG_DEBUG;
    case 'I': return ANDROID_LOG_INFO;
    case 'W': return ANDROID_LOG_WARN;
    case 'E': return ANDROID_LOG_ERROR;
    case 'F': /* FALLTHRU */ /* Not officially supported */
    case 'A': return ANDROID_LOG_FATAL;
    case BOOLEAN_FALSE: /* FALLTHRU */ /* Not Officially supported */
    case 'S': return -1; /* ANDROID_LOG_SUPPRESS */
      /* clang-format on */
  }
  return default_prio;
}

int __android_log_is_loggable_len(int prio, const char* tag, size_t len, int default_prio) {
  int logLevel = __android_log_level(tag, len, default_prio);
  return logLevel >= 0 && prio >= logLevel;
}

int __android_log_is_loggable(int prio, const char* tag, int default_prio) {
  int logLevel = __android_log_level(tag, (tag && *tag) ? strlen(tag) : 0, default_prio);
  return logLevel >= 0 && prio >= logLevel;
}

int __android_log_is_debuggable() {
  static uint32_t serial;
  static struct cache_char tag_cache;
  static const char key[] = "ro.debuggable";
  int ret;

  if (tag_cache.c) { /* ro property does not change after set */
    ret = tag_cache.c == '1';
  } else if (lock()) {
    struct cache_char temp_cache = {{NULL, 0xFFFFFFFF}, '\0'};
    refresh_cache(&temp_cache, key);
    ret = temp_cache.c == '1';
  } else {
    int change_detected = check_cache(&tag_cache.cache);
    uint32_t current_serial = __system_property_area_serial();
    if (current_serial != serial) {
      change_detected = 1;
    }
    if (change_detected) {
      refresh_cache(&tag_cache, key);
      serial = current_serial;
    }
    ret = tag_cache.c == '1';

    unlock();
  }

  return ret;
}

/*
 * For properties that are read often, but generally remain constant.
 * Since a change is rare, we will accept a trylock failure gracefully.
 * Use a separate lock from is_loggable to keep contention down b/25563384.
 */
struct cache2_char {
  pthread_mutex_t lock;
  uint32_t serial;
  const char* key_persist;
  struct cache_char cache_persist;
  const char* key_ro;
  struct cache_char cache_ro;
  unsigned char (*const evaluate)(const struct cache2_char* self);
};

static inline unsigned char do_cache2_char(struct cache2_char* self) {
  uint32_t current_serial;
  int change_detected;
  unsigned char c;

  if (pthread_mutex_trylock(&self->lock)) {
    /* We are willing to accept some race in this context */
    return self->evaluate(self);
  }

  change_detected = check_cache(&self->cache_persist.cache) || check_cache(&self->cache_ro.cache);
  current_serial = __system_property_area_serial();
  if (current_serial != self->serial) {
    change_detected = 1;
  }
  if (change_detected) {
    refresh_cache(&self->cache_persist, self->key_persist);
    refresh_cache(&self->cache_ro, self->key_ro);
    self->serial = current_serial;
  }
  c = self->evaluate(self);

  pthread_mutex_unlock(&self->lock);

  return c;
}

static unsigned char evaluate_persist_ro(const struct cache2_char* self) {
  unsigned char c = self->cache_persist.c;

  if (c) {
    return c;
  }

  return self->cache_ro.c;
}

/*
 * Timestamp state generally remains constant, but can change at any time
 * to handle developer requirements.
 */
clockid_t android_log_clockid() {
  static struct cache2_char clockid = {PTHREAD_MUTEX_INITIALIZER, 0,
                                       "persist.logd.timestamp",  {{NULL, 0xFFFFFFFF}, '\0'},
                                       "ro.logd.timestamp",       {{NULL, 0xFFFFFFFF}, '\0'},
                                       evaluate_persist_ro};

  return (tolower(do_cache2_char(&clockid)) == 'm') ? CLOCK_MONOTONIC : CLOCK_REALTIME;
}

/*
 * Security state generally remains constant, but the DO must be able
 * to turn off logging should it become spammy after an attack is detected.
 */
static unsigned char evaluate_security(const struct cache2_char* self) {
  unsigned char c = self->cache_ro.c;

  return (c != BOOLEAN_FALSE) && c && (self->cache_persist.c == BOOLEAN_TRUE);
}

int __android_log_security() {
  static struct cache2_char security = {
      PTHREAD_MUTEX_INITIALIZER, 0,
      "persist.logd.security",   {{NULL, 0xFFFFFFFF}, BOOLEAN_FALSE},
      "ro.device_owner",         {{NULL, 0xFFFFFFFF}, BOOLEAN_FALSE},
      evaluate_security};

  return do_cache2_char(&security);
}

/*
 * Interface that represents the logd buffer size determination so that others
 * need not guess our intentions.
 */

/* Property helper */
static bool check_flag(const char* prop, const char* flag) {
  const char* cp = strcasestr(prop, flag);
  if (!cp) {
    return false;
  }
  /* We only will document comma (,) */
  static const char sep[] = ",:;|+ \t\f";
  if ((cp != prop) && !strchr(sep, cp[-1])) {
    return false;
  }
  cp += strlen(flag);
  return !*cp || !!strchr(sep, *cp);
}

/* cache structure */
struct cache_property {
  struct cache cache;
  char property[PROP_VALUE_MAX];
};

static void refresh_cache_property(struct cache_property* cache, const char* key) {
  if (!cache->cache.pinfo) {
    cache->cache.pinfo = __system_property_find(key);
    if (!cache->cache.pinfo) {
      return;
    }
  }
  cache->cache.serial = __system_property_serial(cache->cache.pinfo);
  __system_property_read(cache->cache.pinfo, 0, cache->property);
}

/* get boolean with the logger twist that supports eng adjustments */
bool __android_logger_property_get_bool(const char* key, int flag) {
  struct cache_property property = {{NULL, 0xFFFFFFFF}, {0}};
  if (flag & BOOL_DEFAULT_FLAG_PERSIST) {
    char newkey[strlen("persist.") + strlen(key) + 1];
    snprintf(newkey, sizeof(newkey), "ro.%s", key);
    refresh_cache_property(&property, newkey);
    property.cache.pinfo = NULL;
    property.cache.serial = 0xFFFFFFFF;
    snprintf(newkey, sizeof(newkey), "persist.%s", key);
    refresh_cache_property(&property, newkey);
    property.cache.pinfo = NULL;
    property.cache.serial = 0xFFFFFFFF;
  }

  refresh_cache_property(&property, key);

  if (check_flag(property.property, "true")) {
    return true;
  }
  if (check_flag(property.property, "false")) {
    return false;
  }
  if (property.property[0]) {
    flag &= ~(BOOL_DEFAULT_FLAG_ENG | BOOL_DEFAULT_FLAG_SVELTE);
  }
  if (check_flag(property.property, "eng")) {
    flag |= BOOL_DEFAULT_FLAG_ENG;
  }
  /* this is really a "not" flag */
  if (check_flag(property.property, "svelte")) {
    flag |= BOOL_DEFAULT_FLAG_SVELTE;
  }

  /* Sanity Check */
  if (flag & (BOOL_DEFAULT_FLAG_SVELTE | BOOL_DEFAULT_FLAG_ENG)) {
    flag &= ~BOOL_DEFAULT_FLAG_TRUE_FALSE;
    flag |= BOOL_DEFAULT_TRUE;
  }

  if ((flag & BOOL_DEFAULT_FLAG_SVELTE) &&
      __android_logger_property_get_bool("ro.config.low_ram", BOOL_DEFAULT_FALSE)) {
    return false;
  }
  if ((flag & BOOL_DEFAULT_FLAG_ENG) && !__android_log_is_debuggable()) {
    return false;
  }

  return (flag & BOOL_DEFAULT_FLAG_TRUE_FALSE) != BOOL_DEFAULT_FALSE;
}

bool __android_logger_valid_buffer_size(unsigned long value) {
  static long pages, pagesize;
  unsigned long maximum;

  if ((value < LOG_BUFFER_MIN_SIZE) || (LOG_BUFFER_MAX_SIZE < value)) {
    return false;
  }

  if (!pages) {
    pages = sysconf(_SC_PHYS_PAGES);
  }
  if (pages < 1) {
    return true;
  }

  if (!pagesize) {
    pagesize = sysconf(_SC_PAGESIZE);
    if (pagesize <= 1) {
      pagesize = PAGE_SIZE;
    }
  }

  /* maximum memory impact a somewhat arbitrary ~3% */
  pages = (pages + 31) / 32;
  maximum = pages * pagesize;

  if ((maximum < LOG_BUFFER_MIN_SIZE) || (LOG_BUFFER_MAX_SIZE < maximum)) {
    return true;
  }

  return value <= maximum;
}

struct cache2_property_size {
  pthread_mutex_t lock;
  uint32_t serial;
  const char* key_persist;
  struct cache_property cache_persist;
  const char* key_ro;
  struct cache_property cache_ro;
  unsigned long (*const evaluate)(const struct cache2_property_size* self);
};

static inline unsigned long do_cache2_property_size(struct cache2_property_size* self) {
  uint32_t current_serial;
  int change_detected;
  unsigned long v;

  if (pthread_mutex_trylock(&self->lock)) {
    /* We are willing to accept some race in this context */
    return self->evaluate(self);
  }

  change_detected = check_cache(&self->cache_persist.cache) || check_cache(&self->cache_ro.cache);
  current_serial = __system_property_area_serial();
  if (current_serial != self->serial) {
    change_detected = 1;
  }
  if (change_detected) {
    refresh_cache_property(&self->cache_persist, self->key_persist);
    refresh_cache_property(&self->cache_ro, self->key_ro);
    self->serial = current_serial;
  }
  v = self->evaluate(self);

  pthread_mutex_unlock(&self->lock);

  return v;
}

static unsigned long property_get_size_from_cache(const struct cache_property* cache) {
  char* cp;
  unsigned long value = strtoul(cache->property, &cp, 10);

  switch (*cp) {
    case 'm':
    case 'M':
      value *= 1024;
      [[fallthrough]];
    case 'k':
    case 'K':
      value *= 1024;
      [[fallthrough]];
    case '\0':
      break;

    default:
      value = 0;
  }

  if (!__android_logger_valid_buffer_size(value)) {
    value = 0;
  }

  return value;
}

static unsigned long evaluate_property_get_size(const struct cache2_property_size* self) {
  unsigned long size = property_get_size_from_cache(&self->cache_persist);
  if (size) {
    return size;
  }
  return property_get_size_from_cache(&self->cache_ro);
}

unsigned long __android_logger_get_buffer_size(log_id_t logId) {
  static const char global_tunable[] = "persist.logd.size"; /* Settings App */
  static const char global_default[] = "ro.logd.size";      /* BoardConfig.mk */
  static struct cache2_property_size global = {
      /* clang-format off */
    PTHREAD_MUTEX_INITIALIZER, 0,
    global_tunable, { { NULL, 0xFFFFFFFF }, {} },
    global_default, { { NULL, 0xFFFFFFFF }, {} },
    evaluate_property_get_size
      /* clang-format on */
  };
  char key_persist[strlen(global_tunable) + strlen(".security") + 1];
  char key_ro[strlen(global_default) + strlen(".security") + 1];
  struct cache2_property_size local = {
      /* clang-format off */
    PTHREAD_MUTEX_INITIALIZER, 0,
    key_persist, { { NULL, 0xFFFFFFFF }, {} },
    key_ro,      { { NULL, 0xFFFFFFFF }, {} },
    evaluate_property_get_size
      /* clang-format on */
  };
  unsigned long property_size, default_size;

  default_size = do_cache2_property_size(&global);
  if (!default_size) {
    default_size = __android_logger_property_get_bool("ro.config.low_ram", BOOL_DEFAULT_FALSE)
                       ? LOG_BUFFER_MIN_SIZE /* 64K  */
                       : LOG_BUFFER_SIZE;    /* 256K */
  }

  snprintf(key_persist, sizeof(key_persist), "%s.%s", global_tunable,
           android_log_id_to_name(logId));
  snprintf(key_ro, sizeof(key_ro), "%s.%s", global_default, android_log_id_to_name(logId));
  property_size = do_cache2_property_size(&local);

  if (!property_size) {
    property_size = default_size;
  }

  if (!property_size) {
    property_size = LOG_BUFFER_SIZE;
  }

  return property_size;
}

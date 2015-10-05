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

#include <ctype.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#define _REALLY_INCLUDE_SYS__SYSTEM_PROPERTIES_H_
#include <sys/_system_properties.h>

#include <android/log.h>

struct cache {
    const prop_info *pinfo;
    uint32_t serial;
    char c;
};

static void refresh_cache(struct cache *cache, const char *key)
{
    uint32_t serial;
    char buf[PROP_VALUE_MAX];

    if (!cache->pinfo) {
        cache->pinfo = __system_property_find(key);
        if (!cache->pinfo) {
            return;
        }
    }
    serial = __system_property_serial(cache->pinfo);
    if (serial == cache->serial) {
        return;
    }
    cache->serial = serial;
    __system_property_read(cache->pinfo, 0, buf);
    cache->c = buf[0];
}

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

static int __android_log_level(const char *tag, int def)
{
    /* sizeof() is used on this array below */
    static const char log_namespace[] = "persist.log.tag.";
    static const size_t base_offset = 8; /* skip "persist." */
    /* calculate the size of our key temporary buffer */
    const size_t taglen = (tag && *tag) ? strlen(tag) : 0;
    /* sizeof(log_namespace) = strlen(log_namespace) + 1 */
    char key[sizeof(log_namespace) + taglen];
    char *kp;
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
    static char *last_tag;
    static uint32_t global_serial;
    uint32_t current_global_serial;
    static struct cache tag_cache[2] = {
        { NULL, -1, 0 },
        { NULL, -1, 0 }
    };
    static struct cache global_cache[2] = {
        { NULL, -1, 0 },
        { NULL, -1, 0 }
    };

    strcpy(key, log_namespace);

    pthread_mutex_lock(&lock);

    current_global_serial = __system_property_area_serial();

    if (taglen) {
        uint32_t current_local_serial = current_global_serial;

        if (!last_tag || (last_tag[0] != tag[0]) || strcmp(last_tag + 1, tag + 1)) {
            /* invalidate log.tag.<tag> cache */
            for(i = 0; i < (sizeof(tag_cache) / sizeof(tag_cache[0])); ++i) {
                tag_cache[i].pinfo = NULL;
                tag_cache[i].serial = -1;
                tag_cache[i].c = '\0';
            }
            free(last_tag);
            last_tag = NULL;
            current_global_serial = -1;
        }
        if (!last_tag) {
            last_tag = strdup(tag);
        }
        strcpy(key + sizeof(log_namespace) - 1, tag);

        kp = key;
        for(i = 0; i < (sizeof(tag_cache) / sizeof(tag_cache[0])); ++i) {
            if (current_local_serial != global_serial) {
                refresh_cache(&tag_cache[i], kp);
            }

            if (tag_cache[i].c) {
                c = tag_cache[i].c;
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
        break;
    default:
        /* clear '.' after log.tag */
        key[sizeof(log_namespace) - 2] = '\0';

        kp = key;
        for(i = 0; i < (sizeof(global_cache) / sizeof(global_cache[0])); ++i) {
            if (current_global_serial != global_serial) {
                refresh_cache(&global_cache[i], kp);
            }

            if (global_cache[i].c) {
                c = global_cache[i].c;
                break;
            }

            kp = key + base_offset;
        }
        break;
    }

    global_serial = current_global_serial;

    pthread_mutex_unlock(&lock);

    switch (toupper(c)) {
    case 'V': return ANDROID_LOG_VERBOSE;
    case 'D': return ANDROID_LOG_DEBUG;
    case 'I': return ANDROID_LOG_INFO;
    case 'W': return ANDROID_LOG_WARN;
    case 'E': return ANDROID_LOG_ERROR;
    case 'F': /* FALLTHRU */ /* Not officially supported */
    case 'A': return ANDROID_LOG_FATAL;
    case 'S': return -1; /* ANDROID_LOG_SUPPRESS */
    }
    return def;
}

int __android_log_is_loggable(int prio, const char *tag, int def)
{
    int logLevel = __android_log_level(tag, def);
    return logLevel >= 0 && prio >= logLevel;
}

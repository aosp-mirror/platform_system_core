/*
 *  Copyright 2018 Google, Inc
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#ifndef _STATSLOG_H_
#define _STATSLOG_H_

#include <assert.h>
#include <stats_event_list.h>
#include <stdbool.h>
#include <sys/cdefs.h>

#include <cutils/properties.h>

__BEGIN_DECLS

/*
 * These are defined in
 * http://cs/android/frameworks/base/cmds/statsd/src/atoms.proto
 */
#define LMK_KILL_OCCURRED 51
#define LMK_STATE_CHANGED 54
#define LMK_STATE_CHANGE_START 1
#define LMK_STATE_CHANGE_STOP 2

/*
 * The single event tag id for all stats logs.
 * Keep this in sync with system/core/logcat/event.logtags
 */
const static int kStatsEventTag = 1937006964;

static inline void statslog_init(android_log_context* log_ctx, bool* enable_stats_log) {
    assert(log_ctx != NULL);
    assert(enable_stats_log != NULL);
    *enable_stats_log = property_get_bool("ro.lmk.log_stats", false);

    if (*enable_stats_log) {
        *log_ctx = create_android_logger(kStatsEventTag);
    }
}

static inline void statslog_destroy(android_log_context* log_ctx) {
    assert(log_ctx != NULL);
    if (*log_ctx) {
        android_log_destroy(log_ctx);
    }
}

struct memory_stat {
    int64_t pgfault;
    int64_t pgmajfault;
    int64_t rss_in_bytes;
    int64_t cache_in_bytes;
    int64_t swap_in_bytes;
};

#define MEMCG_PROCESS_MEMORY_STAT_PATH "/dev/memcg/apps/uid_%u/pid_%u/memory.stat"

/**
 * Logs the change in LMKD state which is used as start/stop boundaries for logging
 * LMK_KILL_OCCURRED event.
 * Code: LMK_STATE_CHANGED = 54
 */
int
stats_write_lmk_state_changed(android_log_context ctx, int32_t code, int32_t state);

/**
 * Logs the event when LMKD kills a process to reduce memory pressure.
 * Code: LMK_KILL_OCCURRED = 51
 */
int
stats_write_lmk_kill_occurred(android_log_context ctx, int32_t code, int32_t uid,
                              char const* process_name, int32_t oom_score, int64_t pgfault,
                              int64_t pgmajfault, int64_t rss_in_bytes, int64_t cache_in_bytes,
                              int64_t swap_in_bytes);

__END_DECLS

#endif /* _STATSLOG_H_ */

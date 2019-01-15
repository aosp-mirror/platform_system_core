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

#include <assert.h>
#include <errno.h>
#include <log/log_id.h>
#include <stats_event_list.h>
#include <time.h>

static int64_t getElapsedRealTimeNs() {
    struct timespec t;
    t.tv_sec = t.tv_nsec = 0;
    clock_gettime(CLOCK_BOOTTIME, &t);
    return (int64_t)t.tv_sec * 1000000000LL + t.tv_nsec;
}

/**
 * Logs the change in LMKD state which is used as start/stop boundaries for logging
 * LMK_KILL_OCCURRED event.
 * Code: LMK_STATE_CHANGED = 54
 */
int
stats_write_lmk_state_changed(android_log_context ctx, int32_t code, int32_t state) {
    assert(ctx != NULL);
    int ret = -EINVAL;
    if (!ctx) {
        return ret;
    }

    reset_log_context(ctx);

    if ((ret = android_log_write_int64(ctx, getElapsedRealTimeNs())) < 0) {
        return ret;
    }

    if ((ret = android_log_write_int32(ctx, code)) < 0) {
        return ret;
    }

    if ((ret = android_log_write_int32(ctx, state)) < 0) {
        return ret;
    }

    return write_to_logger(ctx, LOG_ID_STATS);
}

/**
 * Logs the event when LMKD kills a process to reduce memory pressure.
 * Code: LMK_KILL_OCCURRED = 51
 */
int
stats_write_lmk_kill_occurred(android_log_context ctx, int32_t code, int32_t uid,
                              char const* process_name, int32_t oom_score, int64_t pgfault,
                              int64_t pgmajfault, int64_t rss_in_bytes, int64_t cache_in_bytes,
                              int64_t swap_in_bytes, int64_t process_start_time_ns) {
    assert(ctx != NULL);
    int ret = -EINVAL;
    if (!ctx) {
        return ret;
    }
    reset_log_context(ctx);

    if ((ret = android_log_write_int64(ctx, getElapsedRealTimeNs())) < 0) {
        return ret;
    }

    if ((ret = android_log_write_int32(ctx, code)) < 0) {
        return ret;
    }

    if ((ret = android_log_write_int32(ctx, uid)) < 0) {
        return ret;
    }

    if ((ret = android_log_write_string8(ctx, (process_name == NULL) ? "" : process_name)) < 0) {
        return ret;
    }

    if ((ret = android_log_write_int32(ctx, oom_score)) < 0) {
        return ret;
    }

    if ((ret = android_log_write_int64(ctx, pgfault)) < 0) {
        return ret;
    }

    if ((ret = android_log_write_int64(ctx, pgmajfault)) < 0) {
        return ret;
    }

    if ((ret = android_log_write_int64(ctx, rss_in_bytes)) < 0) {
        return ret;
    }

    if ((ret = android_log_write_int64(ctx, cache_in_bytes)) < 0) {
        return ret;
    }

    if ((ret = android_log_write_int64(ctx, swap_in_bytes)) < 0) {
        return ret;
    }

    if ((ret = android_log_write_int64(ctx, process_start_time_ns)) < 0) {
        return ret;
    }

    return write_to_logger(ctx, LOG_ID_STATS);
}

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
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define LINE_MAX 128

struct proc {
    int pid;
    char taskname[LINE_MAX];
    struct proc* pidhash_next;
};

#define PIDHASH_SZ 1024
static struct proc** pidhash = NULL;
#define pid_hashfn(x) ((((x) >> 8) ^ (x)) & (PIDHASH_SZ - 1))

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

static struct proc* pid_lookup(int pid) {
    struct proc* procp;

    if (!pidhash) return NULL;

    for (procp = pidhash[pid_hashfn(pid)]; procp && procp->pid != pid; procp = procp->pidhash_next)
        ;

    return procp;
}

/**
 * Logs the event when LMKD kills a process to reduce memory pressure.
 * Code: LMK_KILL_OCCURRED = 51
 */
int
stats_write_lmk_kill_occurred(android_log_context ctx, int32_t code, int32_t uid,
                              char const* process_name, int32_t oom_score, int64_t pgfault,
                              int64_t pgmajfault, int64_t rss_in_bytes, int64_t cache_in_bytes,
                              int64_t swap_in_bytes, int64_t process_start_time_ns,
                              int32_t min_oom_score) {
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

    if ((ret = android_log_write_int32(ctx, min_oom_score)) < 0) {
        return ret;
    }

    return write_to_logger(ctx, LOG_ID_STATS);
}

int stats_write_lmk_kill_occurred_pid(android_log_context ctx, int32_t code, int32_t uid, int pid,
                                      int32_t oom_score, int64_t pgfault, int64_t pgmajfault,
                                      int64_t rss_in_bytes, int64_t cache_in_bytes,
                                      int64_t swap_in_bytes, int64_t process_start_time_ns,
                                      int32_t min_oom_score) {
    struct proc* proc = pid_lookup(pid);
    if (!proc) return -EINVAL;

    return stats_write_lmk_kill_occurred(ctx, code, uid, proc->taskname, oom_score, pgfault,
                                         pgmajfault, rss_in_bytes, cache_in_bytes, swap_in_bytes,
                                         process_start_time_ns, min_oom_score);
}

static void proc_insert(struct proc* procp) {
    if (!pidhash)
        pidhash = calloc(PIDHASH_SZ, sizeof(struct proc));
    int hval = pid_hashfn(procp->pid);
    procp->pidhash_next = pidhash[hval];
    pidhash[hval] = procp;
}

void stats_remove_taskname(int pid) {
    if (!pidhash) return;

    int hval = pid_hashfn(pid);
    struct proc* procp;
    struct proc* prevp;

    for (procp = pidhash[hval], prevp = NULL; procp && procp->pid != pid;
         procp = procp->pidhash_next)
        prevp = procp;

    if (!procp)
        return;

    if (!prevp)
        pidhash[hval] = procp->pidhash_next;
    else
        prevp->pidhash_next = procp->pidhash_next;

    free(procp);
}

void stats_store_taskname(int pid, const char* taskname) {
    struct proc* procp = pid_lookup(pid);
    if (procp != NULL && strcmp(procp->taskname, taskname) == 0)
        return;
    procp = malloc(sizeof(struct proc));
    stats_remove_taskname(pid);
    procp->pid = pid;
    strncpy(procp->taskname, taskname, LINE_MAX - 1);
    procp->taskname[LINE_MAX - 1] = '\0';
    proc_insert(procp);
}

void stats_purge_tasknames() {
    if (!pidhash) return;
    struct proc* procp;
    struct proc* next;
    int i;
    for (i = 0; i < PIDHASH_SZ; i++) {
        procp = pidhash[i];
        while (procp) {
            next = procp->pidhash_next;
            free(procp);
            procp = next;
        }
    }
    memset(pidhash, 0, PIDHASH_SZ * sizeof(struct proc));
}

/*
 * Copyright (C) 2013 The Android Open Source Project
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

#define LOG_TAG "lowmemorykiller"

#include <dirent.h>
#include <errno.h>
#include <inttypes.h>
#include <pwd.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/cdefs.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <cutils/properties.h>
#include <cutils/sched_policy.h>
#include <cutils/sockets.h>
#include <lmkd.h>
#include <log/log.h>
#include <log/log_event_list.h>
#include <log/log_time.h>
#include <psi/psi.h>
#include <system/thread_defs.h>

#ifdef LMKD_LOG_STATS
#include "statslog.h"
#endif

/*
 * Define LMKD_TRACE_KILLS to record lmkd kills in kernel traces
 * to profile and correlate with OOM kills
 */
#ifdef LMKD_TRACE_KILLS

#define ATRACE_TAG ATRACE_TAG_ALWAYS
#include <cutils/trace.h>

#define TRACE_KILL_START(pid) ATRACE_INT(__FUNCTION__, pid);
#define TRACE_KILL_END()      ATRACE_INT(__FUNCTION__, 0);

#else /* LMKD_TRACE_KILLS */

#define TRACE_KILL_START(pid) ((void)(pid))
#define TRACE_KILL_END() ((void)0)

#endif /* LMKD_TRACE_KILLS */

#ifndef __unused
#define __unused __attribute__((__unused__))
#endif

#define MEMCG_SYSFS_PATH "/dev/memcg/"
#define MEMCG_MEMORY_USAGE "/dev/memcg/memory.usage_in_bytes"
#define MEMCG_MEMORYSW_USAGE "/dev/memcg/memory.memsw.usage_in_bytes"
#define ZONEINFO_PATH "/proc/zoneinfo"
#define MEMINFO_PATH "/proc/meminfo"
#define PROC_STATUS_TGID_FIELD "Tgid:"
#define LINE_MAX 128

/* Android Logger event logtags (see event.logtags) */
#define MEMINFO_LOG_TAG 10195355

/* gid containing AID_SYSTEM required */
#define INKERNEL_MINFREE_PATH "/sys/module/lowmemorykiller/parameters/minfree"
#define INKERNEL_ADJ_PATH "/sys/module/lowmemorykiller/parameters/adj"

#define ARRAY_SIZE(x)   (sizeof(x) / sizeof(*(x)))
#define EIGHT_MEGA (1 << 23)

#define TARGET_UPDATE_MIN_INTERVAL_MS 1000

#define NS_PER_MS (NS_PER_SEC / MS_PER_SEC)
#define US_PER_MS (US_PER_SEC / MS_PER_SEC)

/* Defined as ProcessList.SYSTEM_ADJ in ProcessList.java */
#define SYSTEM_ADJ (-900)

#define STRINGIFY(x) STRINGIFY_INTERNAL(x)
#define STRINGIFY_INTERNAL(x) #x

/*
 * PSI monitor tracking window size.
 * PSI monitor generates events at most once per window,
 * therefore we poll memory state for the duration of
 * PSI_WINDOW_SIZE_MS after the event happens.
 */
#define PSI_WINDOW_SIZE_MS 1000
/* Polling period after initial PSI signal */
#define PSI_POLL_PERIOD_MS 10
/* Poll for the duration of one window after initial PSI signal */
#define PSI_POLL_COUNT (PSI_WINDOW_SIZE_MS / PSI_POLL_PERIOD_MS)

#define min(a, b) (((a) < (b)) ? (a) : (b))

#define FAIL_REPORT_RLIMIT_MS 1000

/* default to old in-kernel interface if no memory pressure events */
static bool use_inkernel_interface = true;
static bool has_inkernel_module;

/* memory pressure levels */
enum vmpressure_level {
    VMPRESS_LEVEL_LOW = 0,
    VMPRESS_LEVEL_MEDIUM,
    VMPRESS_LEVEL_CRITICAL,
    VMPRESS_LEVEL_COUNT
};

static const char *level_name[] = {
    "low",
    "medium",
    "critical"
};

struct {
    int64_t min_nr_free_pages; /* recorded but not used yet */
    int64_t max_nr_free_pages;
} low_pressure_mem = { -1, -1 };

struct psi_threshold {
    enum psi_stall_type stall_type;
    int threshold_ms;
};

static int level_oomadj[VMPRESS_LEVEL_COUNT];
static int mpevfd[VMPRESS_LEVEL_COUNT] = { -1, -1, -1 };
static bool debug_process_killing;
static bool enable_pressure_upgrade;
static int64_t upgrade_pressure;
static int64_t downgrade_pressure;
static bool low_ram_device;
static bool kill_heaviest_task;
static unsigned long kill_timeout_ms;
static bool use_minfree_levels;
static bool per_app_memcg;
static int swap_free_low_percentage;
static bool use_psi_monitors = false;
static struct psi_threshold psi_thresholds[VMPRESS_LEVEL_COUNT] = {
    { PSI_SOME, 70 },    /* 70ms out of 1sec for partial stall */
    { PSI_SOME, 100 },   /* 100ms out of 1sec for partial stall */
    { PSI_FULL, 70 },    /* 70ms out of 1sec for complete stall */
};

static android_log_context ctx;

/* data required to handle events */
struct event_handler_info {
    int data;
    void (*handler)(int data, uint32_t events);
};

/* data required to handle socket events */
struct sock_event_handler_info {
    int sock;
    struct event_handler_info handler_info;
};

/* max supported number of data connections */
#define MAX_DATA_CONN 2

/* socket event handler data */
static struct sock_event_handler_info ctrl_sock;
static struct sock_event_handler_info data_sock[MAX_DATA_CONN];

/* vmpressure event handler data */
static struct event_handler_info vmpressure_hinfo[VMPRESS_LEVEL_COUNT];

/* 3 memory pressure levels, 1 ctrl listen socket, 2 ctrl data socket */
#define MAX_EPOLL_EVENTS (1 + MAX_DATA_CONN + VMPRESS_LEVEL_COUNT)
static int epollfd;
static int maxevents;

/* OOM score values used by both kernel and framework */
#define OOM_SCORE_ADJ_MIN       (-1000)
#define OOM_SCORE_ADJ_MAX       1000

static int lowmem_adj[MAX_TARGETS];
static int lowmem_minfree[MAX_TARGETS];
static int lowmem_targets_size;

/* Fields to parse in /proc/zoneinfo */
enum zoneinfo_field {
    ZI_NR_FREE_PAGES = 0,
    ZI_NR_FILE_PAGES,
    ZI_NR_SHMEM,
    ZI_NR_UNEVICTABLE,
    ZI_WORKINGSET_REFAULT,
    ZI_HIGH,
    ZI_FIELD_COUNT
};

static const char* const zoneinfo_field_names[ZI_FIELD_COUNT] = {
    "nr_free_pages",
    "nr_file_pages",
    "nr_shmem",
    "nr_unevictable",
    "workingset_refault",
    "high",
};

union zoneinfo {
    struct {
        int64_t nr_free_pages;
        int64_t nr_file_pages;
        int64_t nr_shmem;
        int64_t nr_unevictable;
        int64_t workingset_refault;
        int64_t high;
        /* fields below are calculated rather than read from the file */
        int64_t totalreserve_pages;
    } field;
    int64_t arr[ZI_FIELD_COUNT];
};

/* Fields to parse in /proc/meminfo */
enum meminfo_field {
    MI_NR_FREE_PAGES = 0,
    MI_CACHED,
    MI_SWAP_CACHED,
    MI_BUFFERS,
    MI_SHMEM,
    MI_UNEVICTABLE,
    MI_TOTAL_SWAP,
    MI_FREE_SWAP,
    MI_ACTIVE_ANON,
    MI_INACTIVE_ANON,
    MI_ACTIVE_FILE,
    MI_INACTIVE_FILE,
    MI_SRECLAIMABLE,
    MI_SUNRECLAIM,
    MI_KERNEL_STACK,
    MI_PAGE_TABLES,
    MI_ION_HELP,
    MI_ION_HELP_POOL,
    MI_CMA_FREE,
    MI_FIELD_COUNT
};

static const char* const meminfo_field_names[MI_FIELD_COUNT] = {
    "MemFree:",
    "Cached:",
    "SwapCached:",
    "Buffers:",
    "Shmem:",
    "Unevictable:",
    "SwapTotal:",
    "SwapFree:",
    "Active(anon):",
    "Inactive(anon):",
    "Active(file):",
    "Inactive(file):",
    "SReclaimable:",
    "SUnreclaim:",
    "KernelStack:",
    "PageTables:",
    "ION_heap:",
    "ION_heap_pool:",
    "CmaFree:",
};

union meminfo {
    struct {
        int64_t nr_free_pages;
        int64_t cached;
        int64_t swap_cached;
        int64_t buffers;
        int64_t shmem;
        int64_t unevictable;
        int64_t total_swap;
        int64_t free_swap;
        int64_t active_anon;
        int64_t inactive_anon;
        int64_t active_file;
        int64_t inactive_file;
        int64_t sreclaimable;
        int64_t sunreclaimable;
        int64_t kernel_stack;
        int64_t page_tables;
        int64_t ion_heap;
        int64_t ion_heap_pool;
        int64_t cma_free;
        /* fields below are calculated rather than read from the file */
        int64_t nr_file_pages;
    } field;
    int64_t arr[MI_FIELD_COUNT];
};

enum field_match_result {
    NO_MATCH,
    PARSE_FAIL,
    PARSE_SUCCESS
};

struct adjslot_list {
    struct adjslot_list *next;
    struct adjslot_list *prev;
};

struct proc {
    struct adjslot_list asl;
    int pid;
    uid_t uid;
    int oomadj;
    struct proc *pidhash_next;
};

struct reread_data {
    const char* const filename;
    int fd;
};

#ifdef LMKD_LOG_STATS
static bool enable_stats_log;
static android_log_context log_ctx;
#endif

#define PIDHASH_SZ 1024
static struct proc *pidhash[PIDHASH_SZ];
#define pid_hashfn(x) ((((x) >> 8) ^ (x)) & (PIDHASH_SZ - 1))

#define ADJTOSLOT(adj) ((adj) + -OOM_SCORE_ADJ_MIN)
#define ADJTOSLOT_COUNT (ADJTOSLOT(OOM_SCORE_ADJ_MAX) + 1)
static struct adjslot_list procadjslot_list[ADJTOSLOT_COUNT];

#define MAX_DISTINCT_OOM_ADJ 32
#define KILLCNT_INVALID_IDX 0xFF
/*
 * Because killcnt array is sparse a two-level indirection is used
 * to keep the size small. killcnt_idx stores index of the element in
 * killcnt array. Index KILLCNT_INVALID_IDX indicates an unused slot.
 */
static uint8_t killcnt_idx[ADJTOSLOT_COUNT];
static uint16_t killcnt[MAX_DISTINCT_OOM_ADJ];
static int killcnt_free_idx = 0;
static uint32_t killcnt_total = 0;

/* PAGE_SIZE / 1024 */
static long page_k;

static bool parse_int64(const char* str, int64_t* ret) {
    char* endptr;
    long long val = strtoll(str, &endptr, 10);
    if (str == endptr || val > INT64_MAX) {
        return false;
    }
    *ret = (int64_t)val;
    return true;
}

static enum field_match_result match_field(const char* cp, const char* ap,
                                   const char* const field_names[],
                                   int field_count, int64_t* field,
                                   int *field_idx) {
    int64_t val;
    int i;

    for (i = 0; i < field_count; i++) {
        if (!strcmp(cp, field_names[i])) {
            *field_idx = i;
            return parse_int64(ap, field) ? PARSE_SUCCESS : PARSE_FAIL;
        }
    }
    return NO_MATCH;
}

/*
 * Read file content from the beginning up to max_len bytes or EOF
 * whichever happens first.
 */
static ssize_t read_all(int fd, char *buf, size_t max_len)
{
    ssize_t ret = 0;
    off_t offset = 0;

    while (max_len > 0) {
        ssize_t r = TEMP_FAILURE_RETRY(pread(fd, buf, max_len, offset));
        if (r == 0) {
            break;
        }
        if (r == -1) {
            return -1;
        }
        ret += r;
        buf += r;
        offset += r;
        max_len -= r;
    }

    return ret;
}

/*
 * Read a new or already opened file from the beginning.
 * If the file has not been opened yet data->fd should be set to -1.
 * To be used with files which are read often and possibly during high
 * memory pressure to minimize file opening which by itself requires kernel
 * memory allocation and might result in a stall on memory stressed system.
 */
static int reread_file(struct reread_data *data, char *buf, size_t buf_size) {
    ssize_t size;

    if (data->fd == -1) {
        data->fd = open(data->filename, O_RDONLY | O_CLOEXEC);
        if (data->fd == -1) {
            ALOGE("%s open: %s", data->filename, strerror(errno));
            return -1;
        }
    }

    size = read_all(data->fd, buf, buf_size - 1);
    if (size < 0) {
        ALOGE("%s read: %s", data->filename, strerror(errno));
        close(data->fd);
        data->fd = -1;
        return -1;
    }
    ALOG_ASSERT((size_t)size < buf_size - 1, "%s too large", data->filename);
    buf[size] = 0;

    return 0;
}

static struct proc *pid_lookup(int pid) {
    struct proc *procp;

    for (procp = pidhash[pid_hashfn(pid)]; procp && procp->pid != pid;
         procp = procp->pidhash_next)
            ;

    return procp;
}

static void adjslot_insert(struct adjslot_list *head, struct adjslot_list *new)
{
    struct adjslot_list *next = head->next;
    new->prev = head;
    new->next = next;
    next->prev = new;
    head->next = new;
}

static void adjslot_remove(struct adjslot_list *old)
{
    struct adjslot_list *prev = old->prev;
    struct adjslot_list *next = old->next;
    next->prev = prev;
    prev->next = next;
}

static struct adjslot_list *adjslot_tail(struct adjslot_list *head) {
    struct adjslot_list *asl = head->prev;

    return asl == head ? NULL : asl;
}

static void proc_slot(struct proc *procp) {
    int adjslot = ADJTOSLOT(procp->oomadj);

    adjslot_insert(&procadjslot_list[adjslot], &procp->asl);
}

static void proc_unslot(struct proc *procp) {
    adjslot_remove(&procp->asl);
}

static void proc_insert(struct proc *procp) {
    int hval = pid_hashfn(procp->pid);

    procp->pidhash_next = pidhash[hval];
    pidhash[hval] = procp;
    proc_slot(procp);
}

static int pid_remove(int pid) {
    int hval = pid_hashfn(pid);
    struct proc *procp;
    struct proc *prevp;

    for (procp = pidhash[hval], prevp = NULL; procp && procp->pid != pid;
         procp = procp->pidhash_next)
            prevp = procp;

    if (!procp)
        return -1;

    if (!prevp)
        pidhash[hval] = procp->pidhash_next;
    else
        prevp->pidhash_next = procp->pidhash_next;

    proc_unslot(procp);
    free(procp);
    return 0;
}

/*
 * Write a string to a file.
 * Returns false if the file does not exist.
 */
static bool writefilestring(const char *path, const char *s,
                            bool err_if_missing) {
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    ssize_t len = strlen(s);
    ssize_t ret;

    if (fd < 0) {
        if (err_if_missing) {
            ALOGE("Error opening %s; errno=%d", path, errno);
        }
        return false;
    }

    ret = TEMP_FAILURE_RETRY(write(fd, s, len));
    if (ret < 0) {
        ALOGE("Error writing %s; errno=%d", path, errno);
    } else if (ret < len) {
        ALOGE("Short write on %s; length=%zd", path, ret);
    }

    close(fd);
    return true;
}

static inline long get_time_diff_ms(struct timespec *from,
                                    struct timespec *to) {
    return (to->tv_sec - from->tv_sec) * (long)MS_PER_SEC +
           (to->tv_nsec - from->tv_nsec) / (long)NS_PER_MS;
}

static int proc_get_tgid(int pid) {
    char path[PATH_MAX];
    char buf[PAGE_SIZE];
    int fd;
    ssize_t size;
    char *pos;
    int64_t tgid = -1;

    snprintf(path, PATH_MAX, "/proc/%d/status", pid);
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }

    size = read_all(fd, buf, sizeof(buf) - 1);
    if (size < 0) {
        goto out;
    }
    buf[size] = 0;

    pos = buf;
    while (true) {
        pos = strstr(pos, PROC_STATUS_TGID_FIELD);
        /* Stop if TGID tag not found or found at the line beginning */
        if (pos == NULL || pos == buf || pos[-1] == '\n') {
            break;
        }
        pos++;
    }

    if (pos == NULL) {
        goto out;
    }

    pos += strlen(PROC_STATUS_TGID_FIELD);
    while (*pos == ' ') pos++;
    parse_int64(pos, &tgid);

out:
    close(fd);
    return (int)tgid;
}

static void cmd_procprio(LMKD_CTRL_PACKET packet) {
    struct proc *procp;
    char path[80];
    char val[20];
    int soft_limit_mult;
    struct lmk_procprio params;
    bool is_system_server;
    struct passwd *pwdrec;
    int tgid;

    lmkd_pack_get_procprio(packet, &params);

    if (params.oomadj < OOM_SCORE_ADJ_MIN ||
        params.oomadj > OOM_SCORE_ADJ_MAX) {
        ALOGE("Invalid PROCPRIO oomadj argument %d", params.oomadj);
        return;
    }

    /* Check if registered process is a thread group leader */
    tgid = proc_get_tgid(params.pid);
    if (tgid >= 0 && tgid != params.pid) {
        ALOGE("Attempt to register a task that is not a thread group leader (tid %d, tgid %d)",
            params.pid, tgid);
        return;
    }

    /* gid containing AID_READPROC required */
    /* CAP_SYS_RESOURCE required */
    /* CAP_DAC_OVERRIDE required */
    snprintf(path, sizeof(path), "/proc/%d/oom_score_adj", params.pid);
    snprintf(val, sizeof(val), "%d", params.oomadj);
    if (!writefilestring(path, val, false)) {
        ALOGW("Failed to open %s; errno=%d: process %d might have been killed",
              path, errno, params.pid);
        /* If this file does not exist the process is dead. */
        return;
    }

    if (use_inkernel_interface) {
        return;
    }

    if (per_app_memcg) {
        if (params.oomadj >= 900) {
            soft_limit_mult = 0;
        } else if (params.oomadj >= 800) {
            soft_limit_mult = 0;
        } else if (params.oomadj >= 700) {
            soft_limit_mult = 0;
        } else if (params.oomadj >= 600) {
            // Launcher should be perceptible, don't kill it.
            params.oomadj = 200;
            soft_limit_mult = 1;
        } else if (params.oomadj >= 500) {
            soft_limit_mult = 0;
        } else if (params.oomadj >= 400) {
            soft_limit_mult = 0;
        } else if (params.oomadj >= 300) {
            soft_limit_mult = 1;
        } else if (params.oomadj >= 200) {
            soft_limit_mult = 8;
        } else if (params.oomadj >= 100) {
            soft_limit_mult = 10;
        } else if (params.oomadj >=   0) {
            soft_limit_mult = 20;
        } else {
            // Persistent processes will have a large
            // soft limit 512MB.
            soft_limit_mult = 64;
        }

        snprintf(path, sizeof(path), MEMCG_SYSFS_PATH
                 "apps/uid_%d/pid_%d/memory.soft_limit_in_bytes",
                 params.uid, params.pid);
        snprintf(val, sizeof(val), "%d", soft_limit_mult * EIGHT_MEGA);

        /*
         * system_server process has no memcg under /dev/memcg/apps but should be
         * registered with lmkd. This is the best way so far to identify it.
         */
        is_system_server = (params.oomadj == SYSTEM_ADJ &&
                            (pwdrec = getpwnam("system")) != NULL &&
                            params.uid == pwdrec->pw_uid);
        writefilestring(path, val, !is_system_server);
    }

    procp = pid_lookup(params.pid);
    if (!procp) {
            procp = malloc(sizeof(struct proc));
            if (!procp) {
                // Oh, the irony.  May need to rebuild our state.
                return;
            }

            procp->pid = params.pid;
            procp->uid = params.uid;
            procp->oomadj = params.oomadj;
            proc_insert(procp);
    } else {
        proc_unslot(procp);
        procp->oomadj = params.oomadj;
        proc_slot(procp);
    }
}

static void cmd_procremove(LMKD_CTRL_PACKET packet) {
    struct lmk_procremove params;

    if (use_inkernel_interface) {
        return;
    }

    lmkd_pack_get_procremove(packet, &params);
    /*
     * WARNING: After pid_remove() procp is freed and can't be used!
     * Therefore placed at the end of the function.
     */
    pid_remove(params.pid);
}

static void cmd_procpurge() {
    int i;
    struct proc *procp;
    struct proc *next;

    if (use_inkernel_interface) {
        return;
    }

    for (i = 0; i <= ADJTOSLOT(OOM_SCORE_ADJ_MAX); i++) {
        procadjslot_list[i].next = &procadjslot_list[i];
        procadjslot_list[i].prev = &procadjslot_list[i];
    }

    for (i = 0; i < PIDHASH_SZ; i++) {
        procp = pidhash[i];
        while (procp) {
            next = procp->pidhash_next;
            free(procp);
            procp = next;
        }
    }
    memset(&pidhash[0], 0, sizeof(pidhash));
}

static void inc_killcnt(int oomadj) {
    int slot = ADJTOSLOT(oomadj);
    uint8_t idx = killcnt_idx[slot];

    if (idx == KILLCNT_INVALID_IDX) {
        /* index is not assigned for this oomadj */
        if (killcnt_free_idx < MAX_DISTINCT_OOM_ADJ) {
            killcnt_idx[slot] = killcnt_free_idx;
            killcnt[killcnt_free_idx] = 1;
            killcnt_free_idx++;
        } else {
            ALOGW("Number of distinct oomadj levels exceeds %d",
                MAX_DISTINCT_OOM_ADJ);
        }
    } else {
        /*
         * wraparound is highly unlikely and is detectable using total
         * counter because it has to be equal to the sum of all counters
         */
        killcnt[idx]++;
    }
    /* increment total kill counter */
    killcnt_total++;
}

static int get_killcnt(int min_oomadj, int max_oomadj) {
    int slot;
    int count = 0;

    if (min_oomadj > max_oomadj)
        return 0;

    /* special case to get total kill count */
    if (min_oomadj > OOM_SCORE_ADJ_MAX)
        return killcnt_total;

    while (min_oomadj <= max_oomadj &&
           (slot = ADJTOSLOT(min_oomadj)) < ADJTOSLOT_COUNT) {
        uint8_t idx = killcnt_idx[slot];
        if (idx != KILLCNT_INVALID_IDX) {
            count += killcnt[idx];
        }
        min_oomadj++;
    }

    return count;
}

static int cmd_getkillcnt(LMKD_CTRL_PACKET packet) {
    struct lmk_getkillcnt params;

    if (use_inkernel_interface) {
        /* kernel driver does not expose this information */
        return 0;
    }

    lmkd_pack_get_getkillcnt(packet, &params);

    return get_killcnt(params.min_oomadj, params.max_oomadj);
}

static void cmd_target(int ntargets, LMKD_CTRL_PACKET packet) {
    int i;
    struct lmk_target target;
    char minfree_str[PROPERTY_VALUE_MAX];
    char *pstr = minfree_str;
    char *pend = minfree_str + sizeof(minfree_str);
    static struct timespec last_req_tm;
    struct timespec curr_tm;

    if (ntargets < 1 || ntargets > (int)ARRAY_SIZE(lowmem_adj))
        return;

    /*
     * Ratelimit minfree updates to once per TARGET_UPDATE_MIN_INTERVAL_MS
     * to prevent DoS attacks
     */
    if (clock_gettime(CLOCK_MONOTONIC_COARSE, &curr_tm) != 0) {
        ALOGE("Failed to get current time");
        return;
    }

    if (get_time_diff_ms(&last_req_tm, &curr_tm) <
        TARGET_UPDATE_MIN_INTERVAL_MS) {
        ALOGE("Ignoring frequent updated to lmkd limits");
        return;
    }

    last_req_tm = curr_tm;

    for (i = 0; i < ntargets; i++) {
        lmkd_pack_get_target(packet, i, &target);
        lowmem_minfree[i] = target.minfree;
        lowmem_adj[i] = target.oom_adj_score;

        pstr += snprintf(pstr, pend - pstr, "%d:%d,", target.minfree,
            target.oom_adj_score);
        if (pstr >= pend) {
            /* if no more space in the buffer then terminate the loop */
            pstr = pend;
            break;
        }
    }

    lowmem_targets_size = ntargets;

    /* Override the last extra comma */
    pstr[-1] = '\0';
    property_set("sys.lmk.minfree_levels", minfree_str);

    if (has_inkernel_module) {
        char minfreestr[128];
        char killpriostr[128];

        minfreestr[0] = '\0';
        killpriostr[0] = '\0';

        for (i = 0; i < lowmem_targets_size; i++) {
            char val[40];

            if (i) {
                strlcat(minfreestr, ",", sizeof(minfreestr));
                strlcat(killpriostr, ",", sizeof(killpriostr));
            }

            snprintf(val, sizeof(val), "%d", use_inkernel_interface ? lowmem_minfree[i] : 0);
            strlcat(minfreestr, val, sizeof(minfreestr));
            snprintf(val, sizeof(val), "%d", use_inkernel_interface ? lowmem_adj[i] : 0);
            strlcat(killpriostr, val, sizeof(killpriostr));
        }

        writefilestring(INKERNEL_MINFREE_PATH, minfreestr, true);
        writefilestring(INKERNEL_ADJ_PATH, killpriostr, true);
    }
}

static void ctrl_data_close(int dsock_idx) {
    struct epoll_event epev;

    ALOGI("closing lmkd data connection");
    if (epoll_ctl(epollfd, EPOLL_CTL_DEL, data_sock[dsock_idx].sock, &epev) == -1) {
        // Log a warning and keep going
        ALOGW("epoll_ctl for data connection socket failed; errno=%d", errno);
    }
    maxevents--;

    close(data_sock[dsock_idx].sock);
    data_sock[dsock_idx].sock = -1;
}

static int ctrl_data_read(int dsock_idx, char *buf, size_t bufsz) {
    int ret = 0;

    ret = TEMP_FAILURE_RETRY(read(data_sock[dsock_idx].sock, buf, bufsz));

    if (ret == -1) {
        ALOGE("control data socket read failed; errno=%d", errno);
    } else if (ret == 0) {
        ALOGE("Got EOF on control data socket");
        ret = -1;
    }

    return ret;
}

static int ctrl_data_write(int dsock_idx, char *buf, size_t bufsz) {
    int ret = 0;

    ret = TEMP_FAILURE_RETRY(write(data_sock[dsock_idx].sock, buf, bufsz));

    if (ret == -1) {
        ALOGE("control data socket write failed; errno=%d", errno);
    } else if (ret == 0) {
        ALOGE("Got EOF on control data socket");
        ret = -1;
    }

    return ret;
}

static void ctrl_command_handler(int dsock_idx) {
    LMKD_CTRL_PACKET packet;
    int len;
    enum lmk_cmd cmd;
    int nargs;
    int targets;
    int kill_cnt;

    len = ctrl_data_read(dsock_idx, (char *)packet, CTRL_PACKET_MAX_SIZE);
    if (len <= 0)
        return;

    if (len < (int)sizeof(int)) {
        ALOGE("Wrong control socket read length len=%d", len);
        return;
    }

    cmd = lmkd_pack_get_cmd(packet);
    nargs = len / sizeof(int) - 1;
    if (nargs < 0)
        goto wronglen;

    switch(cmd) {
    case LMK_TARGET:
        targets = nargs / 2;
        if (nargs & 0x1 || targets > (int)ARRAY_SIZE(lowmem_adj))
            goto wronglen;
        cmd_target(targets, packet);
        break;
    case LMK_PROCPRIO:
        if (nargs != 3)
            goto wronglen;
        cmd_procprio(packet);
        break;
    case LMK_PROCREMOVE:
        if (nargs != 1)
            goto wronglen;
        cmd_procremove(packet);
        break;
    case LMK_PROCPURGE:
        if (nargs != 0)
            goto wronglen;
        cmd_procpurge();
        break;
    case LMK_GETKILLCNT:
        if (nargs != 2)
            goto wronglen;
        kill_cnt = cmd_getkillcnt(packet);
        len = lmkd_pack_set_getkillcnt_repl(packet, kill_cnt);
        if (ctrl_data_write(dsock_idx, (char *)packet, len) != len)
            return;
        break;
    default:
        ALOGE("Received unknown command code %d", cmd);
        return;
    }

    return;

wronglen:
    ALOGE("Wrong control socket read length cmd=%d len=%d", cmd, len);
}

static void ctrl_data_handler(int data, uint32_t events) {
    if (events & EPOLLIN) {
        ctrl_command_handler(data);
    }
}

static int get_free_dsock() {
    for (int i = 0; i < MAX_DATA_CONN; i++) {
        if (data_sock[i].sock < 0) {
            return i;
        }
    }
    return -1;
}

static void ctrl_connect_handler(int data __unused, uint32_t events __unused) {
    struct epoll_event epev;
    int free_dscock_idx = get_free_dsock();

    if (free_dscock_idx < 0) {
        /*
         * Number of data connections exceeded max supported. This should not
         * happen but if it does we drop all existing connections and accept
         * the new one. This prevents inactive connections from monopolizing
         * data socket and if we drop ActivityManager connection it will
         * immediately reconnect.
         */
        for (int i = 0; i < MAX_DATA_CONN; i++) {
            ctrl_data_close(i);
        }
        free_dscock_idx = 0;
    }

    data_sock[free_dscock_idx].sock = accept(ctrl_sock.sock, NULL, NULL);
    if (data_sock[free_dscock_idx].sock < 0) {
        ALOGE("lmkd control socket accept failed; errno=%d", errno);
        return;
    }

    ALOGI("lmkd data connection established");
    /* use data to store data connection idx */
    data_sock[free_dscock_idx].handler_info.data = free_dscock_idx;
    data_sock[free_dscock_idx].handler_info.handler = ctrl_data_handler;
    epev.events = EPOLLIN;
    epev.data.ptr = (void *)&(data_sock[free_dscock_idx].handler_info);
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, data_sock[free_dscock_idx].sock, &epev) == -1) {
        ALOGE("epoll_ctl for data connection socket failed; errno=%d", errno);
        ctrl_data_close(free_dscock_idx);
        return;
    }
    maxevents++;
}

#ifdef LMKD_LOG_STATS
static void memory_stat_parse_line(char* line, struct memory_stat* mem_st) {
    char key[LINE_MAX + 1];
    int64_t value;

    sscanf(line, "%" STRINGIFY(LINE_MAX) "s  %" SCNd64 "", key, &value);

    if (strcmp(key, "total_") < 0) {
        return;
    }

    if (!strcmp(key, "total_pgfault"))
        mem_st->pgfault = value;
    else if (!strcmp(key, "total_pgmajfault"))
        mem_st->pgmajfault = value;
    else if (!strcmp(key, "total_rss"))
        mem_st->rss_in_bytes = value;
    else if (!strcmp(key, "total_cache"))
        mem_st->cache_in_bytes = value;
    else if (!strcmp(key, "total_swap"))
        mem_st->swap_in_bytes = value;
}

static int memory_stat_from_cgroup(struct memory_stat* mem_st, int pid, uid_t uid) {
    FILE *fp;
    char buf[PATH_MAX];

    snprintf(buf, sizeof(buf), MEMCG_PROCESS_MEMORY_STAT_PATH, uid, pid);

    fp = fopen(buf, "r");

    if (fp == NULL) {
        ALOGE("%s open failed: %s", buf, strerror(errno));
        return -1;
    }

    while (fgets(buf, PAGE_SIZE, fp) != NULL) {
        memory_stat_parse_line(buf, mem_st);
    }
    fclose(fp);

    return 0;
}

static int memory_stat_from_procfs(struct memory_stat* mem_st, int pid) {
    char path[PATH_MAX];
    char buffer[PROC_STAT_BUFFER_SIZE];
    int fd, ret;

    snprintf(path, sizeof(path), PROC_STAT_FILE_PATH, pid);
    if ((fd = open(path, O_RDONLY | O_CLOEXEC)) < 0) {
        ALOGE("%s open failed: %s", path, strerror(errno));
        return -1;
    }

    ret = read(fd, buffer, sizeof(buffer));
    if (ret < 0) {
        ALOGE("%s read failed: %s", path, strerror(errno));
        close(fd);
        return -1;
    }
    close(fd);

    // field 10 is pgfault
    // field 12 is pgmajfault
    // field 22 is starttime
    // field 24 is rss_in_pages
    int64_t pgfault = 0, pgmajfault = 0, starttime = 0, rss_in_pages = 0;
    if (sscanf(buffer,
               "%*u %*s %*s %*d %*d %*d %*d %*d %*d %" SCNd64 " %*d "
               "%" SCNd64 " %*d %*u %*u %*d %*d %*d %*d %*d %*d "
               "%" SCNd64 " %*d %" SCNd64 "",
               &pgfault, &pgmajfault, &starttime, &rss_in_pages) != 4) {
        return -1;
    }
    mem_st->pgfault = pgfault;
    mem_st->pgmajfault = pgmajfault;
    mem_st->rss_in_bytes = (rss_in_pages * PAGE_SIZE);
    mem_st->process_start_time_ns = starttime * (NS_PER_SEC / sysconf(_SC_CLK_TCK));
    return 0;
}
#endif

/* /prop/zoneinfo parsing routines */
static int64_t zoneinfo_parse_protection(char *cp) {
    int64_t max = 0;
    long long zoneval;
    char *save_ptr;

    for (cp = strtok_r(cp, "(), ", &save_ptr); cp;
         cp = strtok_r(NULL, "), ", &save_ptr)) {
        zoneval = strtoll(cp, &cp, 0);
        if (zoneval > max) {
            max = (zoneval > INT64_MAX) ? INT64_MAX : zoneval;
        }
    }

    return max;
}

static bool zoneinfo_parse_line(char *line, union zoneinfo *zi) {
    char *cp = line;
    char *ap;
    char *save_ptr;
    int64_t val;
    int field_idx;

    cp = strtok_r(line, " ", &save_ptr);
    if (!cp) {
        return true;
    }

    if (!strcmp(cp, "protection:")) {
        ap = strtok_r(NULL, ")", &save_ptr);
    } else {
        ap = strtok_r(NULL, " ", &save_ptr);
    }

    if (!ap) {
        return true;
    }

    switch (match_field(cp, ap, zoneinfo_field_names,
                        ZI_FIELD_COUNT, &val, &field_idx)) {
    case (PARSE_SUCCESS):
        zi->arr[field_idx] += val;
        break;
    case (NO_MATCH):
        if (!strcmp(cp, "protection:")) {
            zi->field.totalreserve_pages +=
                zoneinfo_parse_protection(ap);
        }
        break;
    case (PARSE_FAIL):
    default:
        return false;
    }
    return true;
}

static int zoneinfo_parse(union zoneinfo *zi) {
    static struct reread_data file_data = {
        .filename = ZONEINFO_PATH,
        .fd = -1,
    };
    char buf[PAGE_SIZE];
    char *save_ptr;
    char *line;

    memset(zi, 0, sizeof(union zoneinfo));

    if (reread_file(&file_data, buf, sizeof(buf)) < 0) {
        return -1;
    }

    for (line = strtok_r(buf, "\n", &save_ptr); line;
         line = strtok_r(NULL, "\n", &save_ptr)) {
        if (!zoneinfo_parse_line(line, zi)) {
            ALOGE("%s parse error", file_data.filename);
            return -1;
        }
    }
    zi->field.totalreserve_pages += zi->field.high;

    return 0;
}

/* /prop/meminfo parsing routines */
static bool meminfo_parse_line(char *line, union meminfo *mi) {
    char *cp = line;
    char *ap;
    char *save_ptr;
    int64_t val;
    int field_idx;
    enum field_match_result match_res;

    cp = strtok_r(line, " ", &save_ptr);
    if (!cp) {
        return false;
    }

    ap = strtok_r(NULL, " ", &save_ptr);
    if (!ap) {
        return false;
    }

    match_res = match_field(cp, ap, meminfo_field_names, MI_FIELD_COUNT,
        &val, &field_idx);
    if (match_res == PARSE_SUCCESS) {
        mi->arr[field_idx] = val / page_k;
    }
    return (match_res != PARSE_FAIL);
}

static int meminfo_parse(union meminfo *mi) {
    static struct reread_data file_data = {
        .filename = MEMINFO_PATH,
        .fd = -1,
    };
    char buf[PAGE_SIZE];
    char *save_ptr;
    char *line;

    memset(mi, 0, sizeof(union meminfo));

    if (reread_file(&file_data, buf, sizeof(buf)) < 0) {
        return -1;
    }

    for (line = strtok_r(buf, "\n", &save_ptr); line;
         line = strtok_r(NULL, "\n", &save_ptr)) {
        if (!meminfo_parse_line(line, mi)) {
            ALOGE("%s parse error", file_data.filename);
            return -1;
        }
    }
    mi->field.nr_file_pages = mi->field.cached + mi->field.swap_cached +
        mi->field.buffers;

    return 0;
}

static void meminfo_log(union meminfo *mi) {
    for (int field_idx = 0; field_idx < MI_FIELD_COUNT; field_idx++) {
        android_log_write_int32(ctx, (int32_t)min(mi->arr[field_idx] * page_k, INT32_MAX));
    }

    android_log_write_list(ctx, LOG_ID_EVENTS);
    android_log_reset(ctx);
}

static int proc_get_size(int pid) {
    char path[PATH_MAX];
    char line[LINE_MAX];
    int fd;
    int rss = 0;
    int total;
    ssize_t ret;

    /* gid containing AID_READPROC required */
    snprintf(path, PATH_MAX, "/proc/%d/statm", pid);
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd == -1)
        return -1;

    ret = read_all(fd, line, sizeof(line) - 1);
    if (ret < 0) {
        close(fd);
        return -1;
    }

    sscanf(line, "%d %d ", &total, &rss);
    close(fd);
    return rss;
}

static char *proc_get_name(int pid) {
    char path[PATH_MAX];
    static char line[LINE_MAX];
    int fd;
    char *cp;
    ssize_t ret;

    /* gid containing AID_READPROC required */
    snprintf(path, PATH_MAX, "/proc/%d/cmdline", pid);
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd == -1)
        return NULL;
    ret = read_all(fd, line, sizeof(line) - 1);
    close(fd);
    if (ret < 0) {
        return NULL;
    }

    cp = strchr(line, ' ');
    if (cp)
        *cp = '\0';

    return line;
}

static struct proc *proc_adj_lru(int oomadj) {
    return (struct proc *)adjslot_tail(&procadjslot_list[ADJTOSLOT(oomadj)]);
}

static struct proc *proc_get_heaviest(int oomadj) {
    struct adjslot_list *head = &procadjslot_list[ADJTOSLOT(oomadj)];
    struct adjslot_list *curr = head->next;
    struct proc *maxprocp = NULL;
    int maxsize = 0;
    while (curr != head) {
        int pid = ((struct proc *)curr)->pid;
        int tasksize = proc_get_size(pid);
        if (tasksize <= 0) {
            struct adjslot_list *next = curr->next;
            pid_remove(pid);
            curr = next;
        } else {
            if (tasksize > maxsize) {
                maxsize = tasksize;
                maxprocp = (struct proc *)curr;
            }
            curr = curr->next;
        }
    }
    return maxprocp;
}

static void set_process_group_and_prio(int pid, SchedPolicy sp, int prio) {
    DIR* d;
    char proc_path[PATH_MAX];
    struct dirent* de;

    snprintf(proc_path, sizeof(proc_path), "/proc/%d/task", pid);
    if (!(d = opendir(proc_path))) {
        ALOGW("Failed to open %s; errno=%d: process pid(%d) might have died", proc_path, errno,
              pid);
        return;
    }

    while ((de = readdir(d))) {
        int t_pid;

        if (de->d_name[0] == '.') continue;
        t_pid = atoi(de->d_name);

        if (!t_pid) {
            ALOGW("Failed to get t_pid for '%s' of pid(%d)", de->d_name, pid);
            continue;
        }

        if (setpriority(PRIO_PROCESS, t_pid, prio) && errno != ESRCH) {
            ALOGW("Unable to raise priority of killing t_pid (%d): errno=%d", t_pid, errno);
        }

        if (set_cpuset_policy(t_pid, sp)) {
            ALOGW("Failed to set_cpuset_policy on pid(%d) t_pid(%d) to %d", pid, t_pid, (int)sp);
            continue;
        }
    }
    closedir(d);
}

static int last_killed_pid = -1;

/* Kill one process specified by procp.  Returns the size of the process killed */
static int kill_one_process(struct proc* procp, int min_oom_score) {
    int pid = procp->pid;
    uid_t uid = procp->uid;
    int tgid;
    char *taskname;
    int tasksize;
    int r;
    int result = -1;

#ifdef LMKD_LOG_STATS
    struct memory_stat mem_st = {};
    int memory_stat_parse_result = -1;
#else
    /* To prevent unused parameter warning */
    (void)(min_oom_score);
#endif

    tgid = proc_get_tgid(pid);
    if (tgid >= 0 && tgid != pid) {
        ALOGE("Possible pid reuse detected (pid %d, tgid %d)!", pid, tgid);
        goto out;
    }

    taskname = proc_get_name(pid);
    if (!taskname) {
        goto out;
    }

    tasksize = proc_get_size(pid);
    if (tasksize <= 0) {
        goto out;
    }

#ifdef LMKD_LOG_STATS
    if (enable_stats_log) {
        if (per_app_memcg) {
            memory_stat_parse_result = memory_stat_from_cgroup(&mem_st, pid, uid);
        } else {
            memory_stat_parse_result = memory_stat_from_procfs(&mem_st, pid);
        }
    }
#endif

    TRACE_KILL_START(pid);

    /* CAP_KILL required */
    r = kill(pid, SIGKILL);

    set_process_group_and_prio(pid, SP_FOREGROUND, ANDROID_PRIORITY_HIGHEST);

    inc_killcnt(procp->oomadj);
    ALOGE("Kill '%s' (%d), uid %d, oom_adj %d to free %ldkB", taskname, pid, uid, procp->oomadj,
          tasksize * page_k);

    TRACE_KILL_END();

    last_killed_pid = pid;

    if (r) {
        ALOGE("kill(%d): errno=%d", pid, errno);
        goto out;
    } else {
#ifdef LMKD_LOG_STATS
        if (memory_stat_parse_result == 0) {
            stats_write_lmk_kill_occurred(log_ctx, LMK_KILL_OCCURRED, uid, taskname,
                    procp->oomadj, mem_st.pgfault, mem_st.pgmajfault, mem_st.rss_in_bytes,
                    mem_st.cache_in_bytes, mem_st.swap_in_bytes, mem_st.process_start_time_ns,
                    min_oom_score);
        } else if (enable_stats_log) {
            stats_write_lmk_kill_occurred(log_ctx, LMK_KILL_OCCURRED, uid, taskname, procp->oomadj,
                                          -1, -1, tasksize * BYTES_IN_KILOBYTE, -1, -1, -1,
                                          min_oom_score);
        }
#endif
        result = tasksize;
    }

out:
    /*
     * WARNING: After pid_remove() procp is freed and can't be used!
     * Therefore placed at the end of the function.
     */
    pid_remove(pid);
    return result;
}

/*
 * Find one process to kill at or above the given oom_adj level.
 * Returns size of the killed process.
 */
static int find_and_kill_process(int min_score_adj) {
    int i;
    int killed_size = 0;

#ifdef LMKD_LOG_STATS
    bool lmk_state_change_start = false;
#endif

    for (i = OOM_SCORE_ADJ_MAX; i >= min_score_adj; i--) {
        struct proc *procp;

        while (true) {
            procp = kill_heaviest_task ?
                proc_get_heaviest(i) : proc_adj_lru(i);

            if (!procp)
                break;

            killed_size = kill_one_process(procp, min_score_adj);
            if (killed_size >= 0) {
#ifdef LMKD_LOG_STATS
                if (enable_stats_log && !lmk_state_change_start) {
                    lmk_state_change_start = true;
                    stats_write_lmk_state_changed(log_ctx, LMK_STATE_CHANGED,
                                                  LMK_STATE_CHANGE_START);
                }
#endif
                break;
            }
        }
        if (killed_size) {
            break;
        }
    }

#ifdef LMKD_LOG_STATS
    if (enable_stats_log && lmk_state_change_start) {
        stats_write_lmk_state_changed(log_ctx, LMK_STATE_CHANGED, LMK_STATE_CHANGE_STOP);
    }
#endif

    return killed_size;
}

static int64_t get_memory_usage(struct reread_data *file_data) {
    int ret;
    int64_t mem_usage;
    char buf[32];

    if (reread_file(file_data, buf, sizeof(buf)) < 0) {
        return -1;
    }

    if (!parse_int64(buf, &mem_usage)) {
        ALOGE("%s parse error", file_data->filename);
        return -1;
    }
    if (mem_usage == 0) {
        ALOGE("No memory!");
        return -1;
    }
    return mem_usage;
}

void record_low_pressure_levels(union meminfo *mi) {
    if (low_pressure_mem.min_nr_free_pages == -1 ||
        low_pressure_mem.min_nr_free_pages > mi->field.nr_free_pages) {
        if (debug_process_killing) {
            ALOGI("Low pressure min memory update from %" PRId64 " to %" PRId64,
                low_pressure_mem.min_nr_free_pages, mi->field.nr_free_pages);
        }
        low_pressure_mem.min_nr_free_pages = mi->field.nr_free_pages;
    }
    /*
     * Free memory at low vmpressure events occasionally gets spikes,
     * possibly a stale low vmpressure event with memory already
     * freed up (no memory pressure should have been reported).
     * Ignore large jumps in max_nr_free_pages that would mess up our stats.
     */
    if (low_pressure_mem.max_nr_free_pages == -1 ||
        (low_pressure_mem.max_nr_free_pages < mi->field.nr_free_pages &&
         mi->field.nr_free_pages - low_pressure_mem.max_nr_free_pages <
         low_pressure_mem.max_nr_free_pages * 0.1)) {
        if (debug_process_killing) {
            ALOGI("Low pressure max memory update from %" PRId64 " to %" PRId64,
                low_pressure_mem.max_nr_free_pages, mi->field.nr_free_pages);
        }
        low_pressure_mem.max_nr_free_pages = mi->field.nr_free_pages;
    }
}

enum vmpressure_level upgrade_level(enum vmpressure_level level) {
    return (enum vmpressure_level)((level < VMPRESS_LEVEL_CRITICAL) ?
        level + 1 : level);
}

enum vmpressure_level downgrade_level(enum vmpressure_level level) {
    return (enum vmpressure_level)((level > VMPRESS_LEVEL_LOW) ?
        level - 1 : level);
}

static bool is_kill_pending(void) {
    char buf[24];

    if (last_killed_pid < 0) {
        return false;
    }

    snprintf(buf, sizeof(buf), "/proc/%d/", last_killed_pid);
    if (access(buf, F_OK) == 0) {
        return true;
    }

    // reset last killed PID because there's nothing pending
    last_killed_pid = -1;
    return false;
}

static void mp_event_common(int data, uint32_t events __unused) {
    int ret;
    unsigned long long evcount;
    int64_t mem_usage, memsw_usage;
    int64_t mem_pressure;
    enum vmpressure_level lvl;
    union meminfo mi;
    union zoneinfo zi;
    struct timespec curr_tm;
    static struct timespec last_kill_tm;
    static unsigned long kill_skip_count = 0;
    enum vmpressure_level level = (enum vmpressure_level)data;
    long other_free = 0, other_file = 0;
    int min_score_adj;
    int minfree = 0;
    static struct reread_data mem_usage_file_data = {
        .filename = MEMCG_MEMORY_USAGE,
        .fd = -1,
    };
    static struct reread_data memsw_usage_file_data = {
        .filename = MEMCG_MEMORYSW_USAGE,
        .fd = -1,
    };

    if (debug_process_killing) {
        ALOGI("%s memory pressure event is triggered", level_name[level]);
    }

    if (!use_psi_monitors) {
        /*
         * Check all event counters from low to critical
         * and upgrade to the highest priority one. By reading
         * eventfd we also reset the event counters.
         */
        for (lvl = VMPRESS_LEVEL_LOW; lvl < VMPRESS_LEVEL_COUNT; lvl++) {
            if (mpevfd[lvl] != -1 &&
                TEMP_FAILURE_RETRY(read(mpevfd[lvl],
                                   &evcount, sizeof(evcount))) > 0 &&
                evcount > 0 && lvl > level) {
                level = lvl;
            }
        }
    }

    if (clock_gettime(CLOCK_MONOTONIC_COARSE, &curr_tm) != 0) {
        ALOGE("Failed to get current time");
        return;
    }

    if (kill_timeout_ms) {
        // If we're within the timeout, see if there's pending reclaim work
        // from the last killed process. If there is (as evidenced by
        // /proc/<pid> continuing to exist), skip killing for now.
        if ((get_time_diff_ms(&last_kill_tm, &curr_tm) < kill_timeout_ms) &&
            (low_ram_device || is_kill_pending())) {
            kill_skip_count++;
            return;
        }
    }

    if (kill_skip_count > 0) {
        ALOGI("%lu memory pressure events were skipped after a kill!",
              kill_skip_count);
        kill_skip_count = 0;
    }

    if (meminfo_parse(&mi) < 0 || zoneinfo_parse(&zi) < 0) {
        ALOGE("Failed to get free memory!");
        return;
    }

    if (use_minfree_levels) {
        int i;

        other_free = mi.field.nr_free_pages - zi.field.totalreserve_pages;
        if (mi.field.nr_file_pages > (mi.field.shmem + mi.field.unevictable + mi.field.swap_cached)) {
            other_file = (mi.field.nr_file_pages - mi.field.shmem -
                          mi.field.unevictable - mi.field.swap_cached);
        } else {
            other_file = 0;
        }

        min_score_adj = OOM_SCORE_ADJ_MAX + 1;
        for (i = 0; i < lowmem_targets_size; i++) {
            minfree = lowmem_minfree[i];
            if (other_free < minfree && other_file < minfree) {
                min_score_adj = lowmem_adj[i];
                break;
            }
        }

        if (min_score_adj == OOM_SCORE_ADJ_MAX + 1) {
            if (debug_process_killing) {
                ALOGI("Ignore %s memory pressure event "
                      "(free memory=%ldkB, cache=%ldkB, limit=%ldkB)",
                      level_name[level], other_free * page_k, other_file * page_k,
                      (long)lowmem_minfree[lowmem_targets_size - 1] * page_k);
            }
            return;
        }

        goto do_kill;
    }

    if (level == VMPRESS_LEVEL_LOW) {
        record_low_pressure_levels(&mi);
    }

    if (level_oomadj[level] > OOM_SCORE_ADJ_MAX) {
        /* Do not monitor this pressure level */
        return;
    }

    if ((mem_usage = get_memory_usage(&mem_usage_file_data)) < 0) {
        goto do_kill;
    }
    if ((memsw_usage = get_memory_usage(&memsw_usage_file_data)) < 0) {
        goto do_kill;
    }

    // Calculate percent for swappinness.
    mem_pressure = (mem_usage * 100) / memsw_usage;

    if (enable_pressure_upgrade && level != VMPRESS_LEVEL_CRITICAL) {
        // We are swapping too much.
        if (mem_pressure < upgrade_pressure) {
            level = upgrade_level(level);
            if (debug_process_killing) {
                ALOGI("Event upgraded to %s", level_name[level]);
            }
        }
    }

    // If we still have enough swap space available, check if we want to
    // ignore/downgrade pressure events.
    if (mi.field.free_swap >=
        mi.field.total_swap * swap_free_low_percentage / 100) {
        // If the pressure is larger than downgrade_pressure lmk will not
        // kill any process, since enough memory is available.
        if (mem_pressure > downgrade_pressure) {
            if (debug_process_killing) {
                ALOGI("Ignore %s memory pressure", level_name[level]);
            }
            return;
        } else if (level == VMPRESS_LEVEL_CRITICAL && mem_pressure > upgrade_pressure) {
            if (debug_process_killing) {
                ALOGI("Downgrade critical memory pressure");
            }
            // Downgrade event, since enough memory available.
            level = downgrade_level(level);
        }
    }

do_kill:
    if (low_ram_device) {
        /* For Go devices kill only one task */
        if (find_and_kill_process(level_oomadj[level]) == 0) {
            if (debug_process_killing) {
                ALOGI("Nothing to kill");
            }
        } else {
            meminfo_log(&mi);
        }
    } else {
        int pages_freed;
        static struct timespec last_report_tm;
        static unsigned long report_skip_count = 0;

        if (!use_minfree_levels) {
            /* Free up enough memory to downgrate the memory pressure to low level */
            if (mi.field.nr_free_pages >= low_pressure_mem.max_nr_free_pages) {
                if (debug_process_killing) {
                    ALOGI("Ignoring pressure since more memory is "
                        "available (%" PRId64 ") than watermark (%" PRId64 ")",
                        mi.field.nr_free_pages, low_pressure_mem.max_nr_free_pages);
                }
                return;
            }
            min_score_adj = level_oomadj[level];
        }

        pages_freed = find_and_kill_process(min_score_adj);

        if (pages_freed == 0) {
            /* Rate limit kill reports when nothing was reclaimed */
            if (get_time_diff_ms(&last_report_tm, &curr_tm) < FAIL_REPORT_RLIMIT_MS) {
                report_skip_count++;
                return;
            }
        } else {
            /* If we killed anything, update the last killed timestamp. */
            last_kill_tm = curr_tm;
        }

        /* Log meminfo whenever we kill or when report rate limit allows */
        meminfo_log(&mi);

        if (use_minfree_levels) {
            ALOGI("Reclaimed %ldkB, cache(%ldkB) and "
                "free(%" PRId64 "kB)-reserved(%" PRId64 "kB) below min(%ldkB) for oom_adj %d",
                pages_freed * page_k,
                other_file * page_k, mi.field.nr_free_pages * page_k,
                zi.field.totalreserve_pages * page_k,
                minfree * page_k, min_score_adj);
        } else {
            ALOGI("Reclaimed %ldkB at oom_adj %d",
                pages_freed * page_k, min_score_adj);
        }

        if (report_skip_count > 0) {
            ALOGI("Suppressed %lu failed kill reports", report_skip_count);
            report_skip_count = 0;
        }

        last_report_tm = curr_tm;
    }
}

static bool init_mp_psi(enum vmpressure_level level) {
    int fd = init_psi_monitor(psi_thresholds[level].stall_type,
        psi_thresholds[level].threshold_ms * US_PER_MS,
        PSI_WINDOW_SIZE_MS * US_PER_MS);

    if (fd < 0) {
        return false;
    }

    vmpressure_hinfo[level].handler = mp_event_common;
    vmpressure_hinfo[level].data = level;
    if (register_psi_monitor(epollfd, fd, &vmpressure_hinfo[level]) < 0) {
        destroy_psi_monitor(fd);
        return false;
    }
    maxevents++;
    mpevfd[level] = fd;

    return true;
}

static void destroy_mp_psi(enum vmpressure_level level) {
    int fd = mpevfd[level];

    if (unregister_psi_monitor(epollfd, fd) < 0) {
        ALOGE("Failed to unregister psi monitor for %s memory pressure; errno=%d",
            level_name[level], errno);
    }
    destroy_psi_monitor(fd);
    mpevfd[level] = -1;
}

static bool init_psi_monitors() {
    if (!init_mp_psi(VMPRESS_LEVEL_LOW)) {
        return false;
    }
    if (!init_mp_psi(VMPRESS_LEVEL_MEDIUM)) {
        destroy_mp_psi(VMPRESS_LEVEL_LOW);
        return false;
    }
    if (!init_mp_psi(VMPRESS_LEVEL_CRITICAL)) {
        destroy_mp_psi(VMPRESS_LEVEL_MEDIUM);
        destroy_mp_psi(VMPRESS_LEVEL_LOW);
        return false;
    }
    return true;
}

static bool init_mp_common(enum vmpressure_level level) {
    int mpfd;
    int evfd;
    int evctlfd;
    char buf[256];
    struct epoll_event epev;
    int ret;
    int level_idx = (int)level;
    const char *levelstr = level_name[level_idx];

    /* gid containing AID_SYSTEM required */
    mpfd = open(MEMCG_SYSFS_PATH "memory.pressure_level", O_RDONLY | O_CLOEXEC);
    if (mpfd < 0) {
        ALOGI("No kernel memory.pressure_level support (errno=%d)", errno);
        goto err_open_mpfd;
    }

    evctlfd = open(MEMCG_SYSFS_PATH "cgroup.event_control", O_WRONLY | O_CLOEXEC);
    if (evctlfd < 0) {
        ALOGI("No kernel memory cgroup event control (errno=%d)", errno);
        goto err_open_evctlfd;
    }

    evfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (evfd < 0) {
        ALOGE("eventfd failed for level %s; errno=%d", levelstr, errno);
        goto err_eventfd;
    }

    ret = snprintf(buf, sizeof(buf), "%d %d %s", evfd, mpfd, levelstr);
    if (ret >= (ssize_t)sizeof(buf)) {
        ALOGE("cgroup.event_control line overflow for level %s", levelstr);
        goto err;
    }

    ret = TEMP_FAILURE_RETRY(write(evctlfd, buf, strlen(buf) + 1));
    if (ret == -1) {
        ALOGE("cgroup.event_control write failed for level %s; errno=%d",
              levelstr, errno);
        goto err;
    }

    epev.events = EPOLLIN;
    /* use data to store event level */
    vmpressure_hinfo[level_idx].data = level_idx;
    vmpressure_hinfo[level_idx].handler = mp_event_common;
    epev.data.ptr = (void *)&vmpressure_hinfo[level_idx];
    ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, evfd, &epev);
    if (ret == -1) {
        ALOGE("epoll_ctl for level %s failed; errno=%d", levelstr, errno);
        goto err;
    }
    maxevents++;
    mpevfd[level] = evfd;
    close(evctlfd);
    return true;

err:
    close(evfd);
err_eventfd:
    close(evctlfd);
err_open_evctlfd:
    close(mpfd);
err_open_mpfd:
    return false;
}

static int init(void) {
    struct epoll_event epev;
    int i;
    int ret;

    page_k = sysconf(_SC_PAGESIZE);
    if (page_k == -1)
        page_k = PAGE_SIZE;
    page_k /= 1024;

    epollfd = epoll_create(MAX_EPOLL_EVENTS);
    if (epollfd == -1) {
        ALOGE("epoll_create failed (errno=%d)", errno);
        return -1;
    }

    // mark data connections as not connected
    for (int i = 0; i < MAX_DATA_CONN; i++) {
        data_sock[i].sock = -1;
    }

    ctrl_sock.sock = android_get_control_socket("lmkd");
    if (ctrl_sock.sock < 0) {
        ALOGE("get lmkd control socket failed");
        return -1;
    }

    ret = listen(ctrl_sock.sock, MAX_DATA_CONN);
    if (ret < 0) {
        ALOGE("lmkd control socket listen failed (errno=%d)", errno);
        return -1;
    }

    epev.events = EPOLLIN;
    ctrl_sock.handler_info.handler = ctrl_connect_handler;
    epev.data.ptr = (void *)&(ctrl_sock.handler_info);
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, ctrl_sock.sock, &epev) == -1) {
        ALOGE("epoll_ctl for lmkd control socket failed (errno=%d)", errno);
        return -1;
    }
    maxevents++;

    has_inkernel_module = !access(INKERNEL_MINFREE_PATH, W_OK);
    use_inkernel_interface = has_inkernel_module;

    if (use_inkernel_interface) {
        ALOGI("Using in-kernel low memory killer interface");
    } else {
        /* Try to use psi monitor first if kernel has it */
        use_psi_monitors = property_get_bool("ro.lmk.use_psi", true) &&
            init_psi_monitors();
        /* Fall back to vmpressure */
        if (!use_psi_monitors &&
            (!init_mp_common(VMPRESS_LEVEL_LOW) ||
            !init_mp_common(VMPRESS_LEVEL_MEDIUM) ||
            !init_mp_common(VMPRESS_LEVEL_CRITICAL))) {
            ALOGE("Kernel does not support memory pressure events or in-kernel low memory killer");
            return -1;
        }
        if (use_psi_monitors) {
            ALOGI("Using psi monitors for memory pressure detection");
        } else {
            ALOGI("Using vmpressure for memory pressure detection");
        }
    }

    for (i = 0; i <= ADJTOSLOT(OOM_SCORE_ADJ_MAX); i++) {
        procadjslot_list[i].next = &procadjslot_list[i];
        procadjslot_list[i].prev = &procadjslot_list[i];
    }

    memset(killcnt_idx, KILLCNT_INVALID_IDX, sizeof(killcnt_idx));

    return 0;
}

static void mainloop(void) {
    struct event_handler_info* handler_info;
    struct event_handler_info* poll_handler = NULL;
    struct timespec last_report_tm, curr_tm;
    struct epoll_event *evt;
    long delay = -1;
    int polling = 0;

    while (1) {
        struct epoll_event events[maxevents];
        int nevents;
        int i;

        if (polling) {
            /* Calculate next timeout */
            clock_gettime(CLOCK_MONOTONIC_COARSE, &curr_tm);
            delay = get_time_diff_ms(&last_report_tm, &curr_tm);
            delay = (delay < PSI_POLL_PERIOD_MS) ?
                PSI_POLL_PERIOD_MS - delay : PSI_POLL_PERIOD_MS;

            /* Wait for events until the next polling timeout */
            nevents = epoll_wait(epollfd, events, maxevents, delay);

            clock_gettime(CLOCK_MONOTONIC_COARSE, &curr_tm);
            if (get_time_diff_ms(&last_report_tm, &curr_tm) >= PSI_POLL_PERIOD_MS) {
                polling--;
                poll_handler->handler(poll_handler->data, 0);
                last_report_tm = curr_tm;
            }
        } else {
            /* Wait for events with no timeout */
            nevents = epoll_wait(epollfd, events, maxevents, -1);
        }

        if (nevents == -1) {
            if (errno == EINTR)
                continue;
            ALOGE("epoll_wait failed (errno=%d)", errno);
            continue;
        }

        /*
         * First pass to see if any data socket connections were dropped.
         * Dropped connection should be handled before any other events
         * to deallocate data connection and correctly handle cases when
         * connection gets dropped and reestablished in the same epoll cycle.
         * In such cases it's essential to handle connection closures first.
         */
        for (i = 0, evt = &events[0]; i < nevents; ++i, evt++) {
            if ((evt->events & EPOLLHUP) && evt->data.ptr) {
                ALOGI("lmkd data connection dropped");
                handler_info = (struct event_handler_info*)evt->data.ptr;
                ctrl_data_close(handler_info->data);
            }
        }

        /* Second pass to handle all other events */
        for (i = 0, evt = &events[0]; i < nevents; ++i, evt++) {
            if (evt->events & EPOLLERR)
                ALOGD("EPOLLERR on event #%d", i);
            if (evt->events & EPOLLHUP) {
                /* This case was handled in the first pass */
                continue;
            }
            if (evt->data.ptr) {
                handler_info = (struct event_handler_info*)evt->data.ptr;
                handler_info->handler(handler_info->data, evt->events);

                if (use_psi_monitors && handler_info->handler == mp_event_common) {
                    /*
                     * Poll for the duration of PSI_WINDOW_SIZE_MS after the
                     * initial PSI event because psi events are rate-limited
                     * at one per sec.
                     */
                    polling = PSI_POLL_COUNT;
                    poll_handler = handler_info;
                    clock_gettime(CLOCK_MONOTONIC_COARSE, &last_report_tm);
                }
            }
        }
    }
}

int main(int argc __unused, char **argv __unused) {
    struct sched_param param = {
            .sched_priority = 1,
    };

    /* By default disable low level vmpressure events */
    level_oomadj[VMPRESS_LEVEL_LOW] =
        property_get_int32("ro.lmk.low", OOM_SCORE_ADJ_MAX + 1);
    level_oomadj[VMPRESS_LEVEL_MEDIUM] =
        property_get_int32("ro.lmk.medium", 800);
    level_oomadj[VMPRESS_LEVEL_CRITICAL] =
        property_get_int32("ro.lmk.critical", 0);
    debug_process_killing = property_get_bool("ro.lmk.debug", false);

    /* By default disable upgrade/downgrade logic */
    enable_pressure_upgrade =
        property_get_bool("ro.lmk.critical_upgrade", false);
    upgrade_pressure =
        (int64_t)property_get_int32("ro.lmk.upgrade_pressure", 100);
    downgrade_pressure =
        (int64_t)property_get_int32("ro.lmk.downgrade_pressure", 100);
    kill_heaviest_task =
        property_get_bool("ro.lmk.kill_heaviest_task", false);
    low_ram_device = property_get_bool("ro.config.low_ram", false);
    kill_timeout_ms =
        (unsigned long)property_get_int32("ro.lmk.kill_timeout_ms", 0);
    use_minfree_levels =
        property_get_bool("ro.lmk.use_minfree_levels", false);
    per_app_memcg =
        property_get_bool("ro.config.per_app_memcg", low_ram_device);
    swap_free_low_percentage =
        property_get_int32("ro.lmk.swap_free_low_percentage", 10);

    ctx = create_android_logger(MEMINFO_LOG_TAG);

#ifdef LMKD_LOG_STATS
    statslog_init(&log_ctx, &enable_stats_log);
#endif

    if (!init()) {
        if (!use_inkernel_interface) {
            /*
             * MCL_ONFAULT pins pages as they fault instead of loading
             * everything immediately all at once. (Which would be bad,
             * because as of this writing, we have a lot of mapped pages we
             * never use.) Old kernels will see MCL_ONFAULT and fail with
             * EINVAL; we ignore this failure.
             *
             * N.B. read the man page for mlockall. MCL_CURRENT | MCL_ONFAULT
             * pins ⊆ MCL_CURRENT, converging to just MCL_CURRENT as we fault
             * in pages.
             */
            /* CAP_IPC_LOCK required */
            if (mlockall(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT) && (errno != EINVAL)) {
                ALOGW("mlockall failed %s", strerror(errno));
            }

            /* CAP_NICE required */
            if (sched_setscheduler(0, SCHED_FIFO, &param)) {
                ALOGW("set SCHED_FIFO failed %s", strerror(errno));
            }
        }

        mainloop();
    }

#ifdef LMKD_LOG_STATS
    statslog_destroy(&log_ctx);
#endif

    android_log_destroy(&ctx);

    ALOGI("exiting");
    return 0;
}

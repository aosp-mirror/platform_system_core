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

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <sched.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/cdefs.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <cutils/properties.h>
#include <cutils/sockets.h>
#include <log/log.h>

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

#define TRACE_KILL_START(pid)
#define TRACE_KILL_END()

#endif /* LMKD_TRACE_KILLS */

#ifndef __unused
#define __unused __attribute__((__unused__))
#endif

#define MEMCG_SYSFS_PATH "/dev/memcg/"
#define MEMCG_MEMORY_USAGE "/dev/memcg/memory.usage_in_bytes"
#define MEMCG_MEMORYSW_USAGE "/dev/memcg/memory.memsw.usage_in_bytes"
#define ZONEINFO_PATH "/proc/zoneinfo"
#define LINE_MAX 128

#define INKERNEL_MINFREE_PATH "/sys/module/lowmemorykiller/parameters/minfree"
#define INKERNEL_ADJ_PATH "/sys/module/lowmemorykiller/parameters/adj"

#define ARRAY_SIZE(x)   (sizeof(x) / sizeof(*(x)))
#define EIGHT_MEGA (1 << 23)

enum lmk_cmd {
    LMK_TARGET,
    LMK_PROCPRIO,
    LMK_PROCREMOVE,
};

#define MAX_TARGETS 6
/*
 * longest is LMK_TARGET followed by MAX_TARGETS each minfree and minkillprio
 * values
 */
#define CTRL_PACKET_MAX (sizeof(int) * (MAX_TARGETS * 2 + 1))

/* default to old in-kernel interface if no memory pressure events */
static int use_inkernel_interface = 1;
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

static int level_oomadj[VMPRESS_LEVEL_COUNT];
static int mpevfd[VMPRESS_LEVEL_COUNT];
static bool debug_process_killing;
static bool enable_pressure_upgrade;
static int64_t upgrade_pressure;
static int64_t downgrade_pressure;
static bool is_go_device;
static bool kill_heaviest_task;

/* control socket listen and data */
static int ctrl_lfd;
static int ctrl_dfd = -1;
static int ctrl_dfd_reopened; /* did we reopen ctrl conn on this loop? */

/* 3 memory pressure levels, 1 ctrl listen socket, 1 ctrl data socket */
#define MAX_EPOLL_EVENTS 5
static int epollfd;
static int maxevents;

/* OOM score values used by both kernel and framework */
#define OOM_SCORE_ADJ_MIN       (-1000)
#define OOM_SCORE_ADJ_MAX       1000

static int lowmem_adj[MAX_TARGETS];
static int lowmem_minfree[MAX_TARGETS];
static int lowmem_targets_size;

struct sysmeminfo {
    int nr_free_pages;
    int nr_file_pages;
    int nr_shmem;
    int totalreserve_pages;
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

#define PIDHASH_SZ 1024
static struct proc *pidhash[PIDHASH_SZ];
#define pid_hashfn(x) ((((x) >> 8) ^ (x)) & (PIDHASH_SZ - 1))

#define ADJTOSLOT(adj) ((adj) + -OOM_SCORE_ADJ_MIN)
static struct adjslot_list procadjslot_list[ADJTOSLOT(OOM_SCORE_ADJ_MAX) + 1];

/* PAGE_SIZE / 1024 */
static long page_k;

static ssize_t read_all(int fd, char *buf, size_t max_len)
{
    ssize_t ret = 0;

    while (max_len > 0) {
        ssize_t r = read(fd, buf, max_len);
        if (r == 0) {
            break;
        }
        if (r == -1) {
            return -1;
        }
        ret += r;
        buf += r;
        max_len -= r;
    }

    return ret;
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

static void writefilestring(const char *path, char *s) {
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    int len = strlen(s);
    int ret;

    if (fd < 0) {
        ALOGE("Error opening %s; errno=%d", path, errno);
        return;
    }

    ret = write(fd, s, len);
    if (ret < 0) {
        ALOGE("Error writing %s; errno=%d", path, errno);
    } else if (ret < len) {
        ALOGE("Short write on %s; length=%d", path, ret);
    }

    close(fd);
}

static void cmd_procprio(int pid, int uid, int oomadj) {
    struct proc *procp;
    char path[80];
    char val[20];
    int soft_limit_mult;

    if (oomadj < OOM_SCORE_ADJ_MIN || oomadj > OOM_SCORE_ADJ_MAX) {
        ALOGE("Invalid PROCPRIO oomadj argument %d", oomadj);
        return;
    }

    snprintf(path, sizeof(path), "/proc/%d/oom_score_adj", pid);
    snprintf(val, sizeof(val), "%d", oomadj);
    writefilestring(path, val);

    if (use_inkernel_interface)
        return;

    if (oomadj >= 900) {
        soft_limit_mult = 0;
    } else if (oomadj >= 800) {
        soft_limit_mult = 0;
    } else if (oomadj >= 700) {
        soft_limit_mult = 0;
    } else if (oomadj >= 600) {
        // Launcher should be perceptible, don't kill it.
        oomadj = 200;
        soft_limit_mult = 1;
    } else if (oomadj >= 500) {
        soft_limit_mult = 0;
    } else if (oomadj >= 400) {
        soft_limit_mult = 0;
    } else if (oomadj >= 300) {
        soft_limit_mult = 1;
    } else if (oomadj >= 200) {
        soft_limit_mult = 2;
    } else if (oomadj >= 100) {
        soft_limit_mult = 10;
    } else if (oomadj >=   0) {
        soft_limit_mult = 20;
    } else {
        // Persistent processes will have a large
        // soft limit 512MB.
        soft_limit_mult = 64;
    }

    snprintf(path, sizeof(path), "/dev/memcg/apps/uid_%d/pid_%d/memory.soft_limit_in_bytes", uid, pid);
    snprintf(val, sizeof(val), "%d", soft_limit_mult * EIGHT_MEGA);
    writefilestring(path, val);

    procp = pid_lookup(pid);
    if (!procp) {
            procp = malloc(sizeof(struct proc));
            if (!procp) {
                // Oh, the irony.  May need to rebuild our state.
                return;
            }

            procp->pid = pid;
            procp->uid = uid;
            procp->oomadj = oomadj;
            proc_insert(procp);
    } else {
        proc_unslot(procp);
        procp->oomadj = oomadj;
        proc_slot(procp);
    }
}

static void cmd_procremove(int pid) {
    if (use_inkernel_interface)
        return;

    pid_remove(pid);
}

static void cmd_target(int ntargets, int *params) {
    int i;

    if (ntargets > (int)ARRAY_SIZE(lowmem_adj))
        return;

    for (i = 0; i < ntargets; i++) {
        lowmem_minfree[i] = ntohl(*params++);
        lowmem_adj[i] = ntohl(*params++);
    }

    lowmem_targets_size = ntargets;

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

        writefilestring(INKERNEL_MINFREE_PATH, minfreestr);
        writefilestring(INKERNEL_ADJ_PATH, killpriostr);
    }
}

static void ctrl_data_close(void) {
    ALOGI("Closing Activity Manager data connection");
    close(ctrl_dfd);
    ctrl_dfd = -1;
    maxevents--;
}

static int ctrl_data_read(char *buf, size_t bufsz) {
    int ret = 0;

    ret = read(ctrl_dfd, buf, bufsz);

    if (ret == -1) {
        ALOGE("control data socket read failed; errno=%d", errno);
    } else if (ret == 0) {
        ALOGE("Got EOF on control data socket");
        ret = -1;
    }

    return ret;
}

static void ctrl_command_handler(void) {
    int ibuf[CTRL_PACKET_MAX / sizeof(int)];
    int len;
    int cmd = -1;
    int nargs;
    int targets;

    len = ctrl_data_read((char *)ibuf, CTRL_PACKET_MAX);
    if (len <= 0)
        return;

    nargs = len / sizeof(int) - 1;
    if (nargs < 0)
        goto wronglen;

    cmd = ntohl(ibuf[0]);

    switch(cmd) {
    case LMK_TARGET:
        targets = nargs / 2;
        if (nargs & 0x1 || targets > (int)ARRAY_SIZE(lowmem_adj))
            goto wronglen;
        cmd_target(targets, &ibuf[1]);
        break;
    case LMK_PROCPRIO:
        if (nargs != 3)
            goto wronglen;
        cmd_procprio(ntohl(ibuf[1]), ntohl(ibuf[2]), ntohl(ibuf[3]));
        break;
    case LMK_PROCREMOVE:
        if (nargs != 1)
            goto wronglen;
        cmd_procremove(ntohl(ibuf[1]));
        break;
    default:
        ALOGE("Received unknown command code %d", cmd);
        return;
    }

    return;

wronglen:
    ALOGE("Wrong control socket read length cmd=%d len=%d", cmd, len);
}

static void ctrl_data_handler(uint32_t events) {
    if (events & EPOLLHUP) {
        ALOGI("ActivityManager disconnected");
        if (!ctrl_dfd_reopened)
            ctrl_data_close();
    } else if (events & EPOLLIN) {
        ctrl_command_handler();
    }
}

static void ctrl_connect_handler(uint32_t events __unused) {
    struct epoll_event epev;

    if (ctrl_dfd >= 0) {
        ctrl_data_close();
        ctrl_dfd_reopened = 1;
    }

    ctrl_dfd = accept(ctrl_lfd, NULL, NULL);

    if (ctrl_dfd < 0) {
        ALOGE("lmkd control socket accept failed; errno=%d", errno);
        return;
    }

    ALOGI("ActivityManager connected");
    maxevents++;
    epev.events = EPOLLIN;
    epev.data.ptr = (void *)ctrl_data_handler;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, ctrl_dfd, &epev) == -1) {
        ALOGE("epoll_ctl for data connection socket failed; errno=%d", errno);
        ctrl_data_close();
        return;
    }
}

static int zoneinfo_parse_protection(char *cp) {
    int max = 0;
    int zoneval;
    char *save_ptr;

    for (cp = strtok_r(cp, "(), ", &save_ptr); cp; cp = strtok_r(NULL, "), ", &save_ptr)) {
        zoneval = strtol(cp, &cp, 0);
        if (zoneval > max)
            max = zoneval;
    }

    return max;
}

static void zoneinfo_parse_line(char *line, struct sysmeminfo *mip) {
    char *cp = line;
    char *ap;
    char *save_ptr;

    cp = strtok_r(line, " ", &save_ptr);
    if (!cp)
        return;

    ap = strtok_r(NULL, " ", &save_ptr);
    if (!ap)
        return;

    if (!strcmp(cp, "nr_free_pages"))
        mip->nr_free_pages += strtol(ap, NULL, 0);
    else if (!strcmp(cp, "nr_file_pages"))
        mip->nr_file_pages += strtol(ap, NULL, 0);
    else if (!strcmp(cp, "nr_shmem"))
        mip->nr_shmem += strtol(ap, NULL, 0);
    else if (!strcmp(cp, "high"))
        mip->totalreserve_pages += strtol(ap, NULL, 0);
    else if (!strcmp(cp, "protection:"))
        mip->totalreserve_pages += zoneinfo_parse_protection(ap);
}

static int zoneinfo_parse(struct sysmeminfo *mip) {
    int fd;
    ssize_t size;
    char buf[PAGE_SIZE];
    char *save_ptr;
    char *line;

    memset(mip, 0, sizeof(struct sysmeminfo));

    fd = open(ZONEINFO_PATH, O_RDONLY | O_CLOEXEC);
    if (fd == -1) {
        ALOGE("%s open: errno=%d", ZONEINFO_PATH, errno);
        return -1;
    }

    size = read_all(fd, buf, sizeof(buf) - 1);
    if (size < 0) {
        ALOGE("%s read: errno=%d", ZONEINFO_PATH, errno);
        close(fd);
        return -1;
    }
    ALOG_ASSERT((size_t)size < sizeof(buf) - 1, "/proc/zoneinfo too large");
    buf[size] = 0;

    for (line = strtok_r(buf, "\n", &save_ptr); line; line = strtok_r(NULL, "\n", &save_ptr))
            zoneinfo_parse_line(line, mip);

    close(fd);
    return 0;
}

static int proc_get_size(int pid) {
    char path[PATH_MAX];
    char line[LINE_MAX];
    int fd;
    int rss = 0;
    int total;
    ssize_t ret;

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

/* Kill one process specified by procp.  Returns the size of the process killed */
static int kill_one_process(struct proc* procp, int min_score_adj,
                            enum vmpressure_level level) {
    int pid = procp->pid;
    uid_t uid = procp->uid;
    char *taskname;
    int tasksize;
    int r;

    taskname = proc_get_name(pid);
    if (!taskname) {
        pid_remove(pid);
        return -1;
    }

    tasksize = proc_get_size(pid);
    if (tasksize <= 0) {
        pid_remove(pid);
        return -1;
    }

    TRACE_KILL_START(pid);

    r = kill(pid, SIGKILL);
    ALOGI(
        "Killing '%s' (%d), uid %d, adj %d\n"
        "   to free %ldkB because system is under %s memory pressure oom_adj %d\n",
        taskname, pid, uid, procp->oomadj, tasksize * page_k,
        level_name[level], min_score_adj);
    pid_remove(pid);

    TRACE_KILL_END();

    if (r) {
        ALOGE("kill(%d): errno=%d", pid, errno);
        return -1;
    }

    return tasksize;
}

/*
 * Find a process to kill based on the current (possibly estimated) free memory
 * and cached memory sizes.  Returns the size of the killed processes.
 */
static int find_and_kill_process(enum vmpressure_level level) {
    int i;
    int killed_size = 0;
    int min_score_adj = level_oomadj[level];

    for (i = OOM_SCORE_ADJ_MAX; i >= min_score_adj; i--) {
        struct proc *procp;

retry:
        if (kill_heaviest_task)
            procp = proc_get_heaviest(i);
        else
            procp = proc_adj_lru(i);

        if (procp) {
            killed_size = kill_one_process(procp, min_score_adj, level);
            if (killed_size < 0) {
                goto retry;
            } else {
                return killed_size;
            }
        }
    }

    return 0;
}

static int64_t get_memory_usage(const char* path) {
    int ret;
    int64_t mem_usage;
    char buf[32];
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd == -1) {
        ALOGE("%s open: errno=%d", path, errno);
        return -1;
    }

    ret = read_all(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (ret < 0) {
        ALOGE("%s error: errno=%d", path, errno);
        return -1;
    }
    sscanf(buf, "%" SCNd64, &mem_usage);
    if (mem_usage == 0) {
        ALOGE("No memory!");
        return -1;
    }
    return mem_usage;
}

enum vmpressure_level upgrade_level(enum vmpressure_level level) {
    return (enum vmpressure_level)((level < VMPRESS_LEVEL_CRITICAL) ?
        level + 1 : level);
}

enum vmpressure_level downgrade_level(enum vmpressure_level level) {
    return (enum vmpressure_level)((level > VMPRESS_LEVEL_LOW) ?
        level - 1 : level);
}

static void mp_event_common(enum vmpressure_level level) {
    int ret;
    unsigned long long evcount;
    int64_t mem_usage, memsw_usage;
    int64_t mem_pressure;

    ret = read(mpevfd[level], &evcount, sizeof(evcount));
    if (ret < 0)
        ALOGE("Error reading memory pressure event fd; errno=%d",
              errno);

    mem_usage = get_memory_usage(MEMCG_MEMORY_USAGE);
    memsw_usage = get_memory_usage(MEMCG_MEMORYSW_USAGE);
    if (memsw_usage < 0 || mem_usage < 0) {
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

    // If the pressure is larger than downgrade_pressure lmk will not
    // kill any process, since enough memory is available.
    if (mem_pressure > downgrade_pressure) {
        if (debug_process_killing) {
            ALOGI("Ignore %s memory pressure", level_name[level]);
        }
        return;
    } else if (level == VMPRESS_LEVEL_CRITICAL &&
               mem_pressure > upgrade_pressure) {
        if (debug_process_killing) {
            ALOGI("Downgrade critical memory pressure");
        }
        // Downgrade event, since enough memory available.
        level = downgrade_level(level);
    }

do_kill:
    if (find_and_kill_process(level) == 0) {
        if (debug_process_killing) {
            ALOGI("Nothing to kill");
        }
    }
}

static void mp_event_low(uint32_t events __unused) {
    mp_event_common(VMPRESS_LEVEL_LOW);
}

static void mp_event_medium(uint32_t events __unused) {
    mp_event_common(VMPRESS_LEVEL_MEDIUM);
}

static void mp_event_critical(uint32_t events __unused) {
    mp_event_common(VMPRESS_LEVEL_CRITICAL);
}

static bool init_mp_common(void *event_handler, enum vmpressure_level level) {
    int mpfd;
    int evfd;
    int evctlfd;
    char buf[256];
    struct epoll_event epev;
    int ret;
    const char *levelstr = level_name[level];

    if (level_oomadj[level] > OOM_SCORE_ADJ_MAX) {
        ALOGI("%s pressure events are disabled", levelstr);
        return true;
    }

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

    ret = write(evctlfd, buf, strlen(buf) + 1);
    if (ret == -1) {
        ALOGE("cgroup.event_control write failed for level %s; errno=%d",
              levelstr, errno);
        goto err;
    }

    epev.events = EPOLLIN;
    epev.data.ptr = event_handler;
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

    ctrl_lfd = android_get_control_socket("lmkd");
    if (ctrl_lfd < 0) {
        ALOGE("get lmkd control socket failed");
        return -1;
    }

    ret = listen(ctrl_lfd, 1);
    if (ret < 0) {
        ALOGE("lmkd control socket listen failed (errno=%d)", errno);
        return -1;
    }

    epev.events = EPOLLIN;
    epev.data.ptr = (void *)ctrl_connect_handler;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, ctrl_lfd, &epev) == -1) {
        ALOGE("epoll_ctl for lmkd control socket failed (errno=%d)", errno);
        return -1;
    }
    maxevents++;

    has_inkernel_module = !access(INKERNEL_MINFREE_PATH, W_OK);
    use_inkernel_interface = has_inkernel_module && !is_go_device;

    if (use_inkernel_interface) {
        ALOGI("Using in-kernel low memory killer interface");
    } else {
        if (!init_mp_common((void *)&mp_event_low, VMPRESS_LEVEL_LOW) ||
            !init_mp_common((void *)&mp_event_medium, VMPRESS_LEVEL_MEDIUM) ||
            !init_mp_common((void *)&mp_event_critical,
                            VMPRESS_LEVEL_CRITICAL)) {
            ALOGE("Kernel does not support memory pressure events or in-kernel low memory killer");
            return -1;
        }
    }

    for (i = 0; i <= ADJTOSLOT(OOM_SCORE_ADJ_MAX); i++) {
        procadjslot_list[i].next = &procadjslot_list[i];
        procadjslot_list[i].prev = &procadjslot_list[i];
    }

    return 0;
}

static void mainloop(void) {
    while (1) {
        struct epoll_event events[maxevents];
        int nevents;
        int i;

        ctrl_dfd_reopened = 0;
        nevents = epoll_wait(epollfd, events, maxevents, -1);

        if (nevents == -1) {
            if (errno == EINTR)
                continue;
            ALOGE("epoll_wait failed (errno=%d)", errno);
            continue;
        }

        for (i = 0; i < nevents; ++i) {
            if (events[i].events & EPOLLERR)
                ALOGD("EPOLLERR on event #%d", i);
            if (events[i].data.ptr)
                (*(void (*)(uint32_t))events[i].data.ptr)(events[i].events);
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
        property_get_bool("ro.lmk.kill_heaviest_task", true);
    is_go_device = property_get_bool("ro.config.low_ram", false);

    // MCL_ONFAULT pins pages as they fault instead of loading
    // everything immediately all at once. (Which would be bad,
    // because as of this writing, we have a lot of mapped pages we
    // never use.) Old kernels will see MCL_ONFAULT and fail with
    // EINVAL; we ignore this failure.
    //
    // N.B. read the man page for mlockall. MCL_CURRENT | MCL_ONFAULT
    // pins ⊆ MCL_CURRENT, converging to just MCL_CURRENT as we fault
    // in pages.
    if (mlockall(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT) && errno != EINVAL)
        ALOGW("mlockall failed: errno=%d", errno);

    sched_setscheduler(0, SCHED_FIFO, &param);
    if (!init())
        mainloop();

    ALOGI("exiting");
    return 0;
}

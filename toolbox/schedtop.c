#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>

#include <stdint.h>
#include <string.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <signal.h>

#include <pwd.h>

struct thread_info {
    int pid;
    int tid;
    char name[64];
    uint64_t exec_time;
    uint64_t delay_time;
    uint32_t run_count;
};

struct thread_table {
    size_t allocated;
    size_t active;
    struct thread_info *data;
};

enum {
    FLAG_BATCH = 1U << 0,
    FLAG_HIDE_IDLE = 1U << 1,
    FLAG_SHOW_THREADS = 1U << 2,
    FLAG_USE_ALTERNATE_SCREEN = 1U << 3,
};

static int time_dp = 9;
static int time_div = 1;
#define NS_TO_S_D(ns) \
    (uint32_t)((ns) / 1000000000), time_dp, ((uint32_t)((ns) % 1000000000) / time_div)

struct thread_table processes;
struct thread_table last_processes;
struct thread_table threads;
struct thread_table last_threads;

static void grow_table(struct thread_table *table)
{
    size_t size = table->allocated;
    struct thread_info *new_table;
    if (size < 128)
        size = 128;
    else
        size *= 2;
    
    new_table = realloc(table->data, size * sizeof(*table->data));
    if (new_table == NULL) {
        fprintf(stderr, "out of memory\n");
        exit(1);
    }
    table->data = new_table;
    table->allocated = size;
}

static struct thread_info *get_item(struct thread_table *table)
{
    if (table->active >= table->allocated)
        grow_table(table);
    return table->data + table->active;
}

static void commit_item(struct thread_table *table)
{
    table->active++;
}

static int read_line(char *line, size_t line_size)
{
    int fd;
    int len;
    fd = open(line, O_RDONLY);
    if(fd == 0)
        return -1;
    len = read(fd, line, line_size - 1);
    close(fd);
    if (len <= 0)
        return -1;
    line[len] = '\0';
    return 0;
}

static void add_thread(int pid, int tid, struct thread_info *proc_info)
{
    char line[1024];
    char *name, *name_end;
    size_t name_len;
    struct thread_info *info;
    if(tid == 0)
        info = get_item(&processes);
    else
        info = get_item(&threads);
    info->pid = pid;
    info->tid = tid;

    if(tid)
        sprintf(line, "/proc/%d/task/%d/schedstat", pid, tid);
    else
        sprintf(line, "/proc/%d/schedstat", pid);
    if (read_line(line, sizeof(line)))
        return;
    if(sscanf(line, "%llu %llu %u", &info->exec_time, &info->delay_time, &info->run_count) != 3)
        return;
    if (proc_info) {
        proc_info->exec_time += info->exec_time;
        proc_info->delay_time += info->delay_time;
        proc_info->run_count += info->run_count;
    }

    name = NULL;
    if (!tid) {
        sprintf(line, "/proc/%d/cmdline", pid);
        if (read_line(line, sizeof(line)) == 0 && line[0]) {
            name = line;
            name_len = strlen(name);
        }
    }
    if (!name) {
        if (tid)
            sprintf(line, "/proc/%d/task/%d/stat", pid, tid);
        else
            sprintf(line, "/proc/%d/stat", pid);
        if (read_line(line, sizeof(line)))
            return;
        name = strchr(line, '(');
        if (name == NULL)
            return;
        name_end = strchr(name, ')');
        if (name_end == NULL)
            return;
        name++;
        name_len = name_end - name;
    }
    if (name_len >= sizeof(info->name))
        name_len = sizeof(info->name) - 1;
    memcpy(info->name, name, name_len);
    info->name[name_len] = '\0';
    if(tid == 0)
        commit_item(&processes);
    else
        commit_item(&threads);
}

static void add_threads(int pid, struct thread_info *proc_info)
{
    char path[1024];
    DIR *d;
    struct dirent *de;
    sprintf(path, "/proc/%d/task", pid);
    d = opendir(path);
    if(d == 0) return;
    while((de = readdir(d)) != 0){
        if(isdigit(de->d_name[0])){
            int tid = atoi(de->d_name);
            add_thread(pid, tid, proc_info);
        }
    }
    closedir(d);
}

static void print_threads(int pid, uint32_t flags)
{
    size_t i, j;
    for (i = 0; i < last_threads.active; i++) {
        int epid = last_threads.data[i].pid;
        int tid = last_threads.data[i].tid;
        if (epid != pid)
            continue;
        for (j = 0; j < threads.active; j++)
            if (tid == threads.data[j].tid)
                break;
        if (j == threads.active)
            printf(" %5u died\n", tid);
        else if (!(flags & FLAG_HIDE_IDLE) || threads.data[j].run_count - last_threads.data[i].run_count)
            printf(" %5u %2u.%0*u %2u.%0*u %5u %5u.%0*u %5u.%0*u %7u  %s\n", tid,
                NS_TO_S_D(threads.data[j].exec_time - last_threads.data[i].exec_time),
                NS_TO_S_D(threads.data[j].delay_time - last_threads.data[i].delay_time),
                threads.data[j].run_count - last_threads.data[i].run_count,
                NS_TO_S_D(threads.data[j].exec_time), NS_TO_S_D(threads.data[j].delay_time),
                threads.data[j].run_count, threads.data[j].name);
    }
}

static void update_table(DIR *d, uint32_t flags)
{
    size_t i, j;
    struct dirent *de;
    
    rewinddir(d);
    while((de = readdir(d)) != 0){
        if(isdigit(de->d_name[0])){
            int pid = atoi(de->d_name);
            struct thread_info *proc_info;
            add_thread(pid, 0, NULL);
            proc_info = &processes.data[processes.active - 1];
            proc_info->exec_time = 0;
            proc_info->delay_time = 0;
            proc_info->run_count = 0;
            add_threads(pid, proc_info);
        }
    }
    if (!(flags & FLAG_BATCH))
        printf("\e[H\e[0J");
    printf("Processes: %d, Threads %d\n", processes.active, threads.active);
    switch (time_dp) {
    case 3:
        printf("   TID --- SINCE LAST ---- ---------- TOTAL ----------\n");
        printf("  PID  EXEC_T  DELAY SCHED EXEC_TIME DELAY_TIM   SCHED NAME\n");
        break;
    case 6:
        printf("   TID ------ SINCE LAST -------    ------------ TOTAL -----------\n");
        printf("  PID  EXEC_TIME DELAY_TIM SCHED    EXEC_TIME   DELAY_TIME   SCHED NAME\n");
        break;
    default:
        printf("   TID    -------- SINCE LAST --------       ------------- TOTAL -------------\n");
        printf("  PID     EXEC_TIME   DELAY_TIME SCHED       EXEC_TIME      DELAY_TIME   SCHED NAME\n");
        break;
    }
    for (i = 0; i < last_processes.active; i++) {
        int pid = last_processes.data[i].pid;
        int tid = last_processes.data[i].tid;
        for (j = 0; j < processes.active; j++)
            if (pid == processes.data[j].pid)
                break;
        if (j == processes.active)
            printf("%5u died\n", pid);
        else if (!(flags & FLAG_HIDE_IDLE) || processes.data[j].run_count - last_processes.data[i].run_count) {
            printf("%5u  %2u.%0*u %2u.%0*u %5u %5u.%0*u %5u.%0*u %7u %s\n", pid,
                NS_TO_S_D(processes.data[j].exec_time - last_processes.data[i].exec_time),
                NS_TO_S_D(processes.data[j].delay_time - last_processes.data[i].delay_time),
                processes.data[j].run_count - last_processes.data[i].run_count,
                NS_TO_S_D(processes.data[j].exec_time), NS_TO_S_D(processes.data[j].delay_time),
                processes.data[j].run_count, processes.data[j].name);
            if (flags & FLAG_SHOW_THREADS)
                print_threads(pid, flags);
        }
    }

    {
        struct thread_table tmp;
        tmp = last_processes;
        last_processes = processes;
        processes = tmp;
        processes.active = 0;
        tmp = last_threads;
        last_threads = threads;
        threads = tmp;
        threads.active = 0;
    }
}

void
sig_abort(int signum)
{
    printf("\e[?47l");
    exit(0);
}


int schedtop_main(int argc, char **argv)
{
    int c;
    DIR *d;
    struct dirent *de;
    char *namefilter = 0;
    int pidfilter = 0;
    uint32_t flags = 0;    
    int delay = 3000000;
    float delay_f;

    while(1) {
        c = getopt(argc, argv, "d:ibtamun");
        if (c == EOF)
            break;
        switch (c) {
        case 'd':
            delay_f = atof(optarg);
            delay = delay_f * 1000000;
            break;
        case 'b':
            flags |= FLAG_BATCH;
            break;
        case 'i':
            flags |= FLAG_HIDE_IDLE;
            break;
        case 't':
            flags |= FLAG_SHOW_THREADS;
            break;
        case 'a':
            flags |= FLAG_USE_ALTERNATE_SCREEN;
            break;
        case 'm':
            time_dp = 3;
            time_div = 1000000;
            break;
        case 'u':
            time_dp = 6;
            time_div = 1000;
            break;
        case 'n':
            time_dp = 9;
            time_div = 1;
            break;
        }
    }

    d = opendir("/proc");
    if(d == 0) return -1;

    if (!(flags & FLAG_BATCH)) {
        if(flags & FLAG_USE_ALTERNATE_SCREEN) {
            signal(SIGINT, sig_abort);
            signal(SIGPIPE, sig_abort);
            signal(SIGTERM, sig_abort);
            printf("\e7\e[?47h");
        }
        printf("\e[2J");
    }
    while (1) {
        update_table(d, flags);
        usleep(delay);
    }
    closedir(d);
    return 0;
}

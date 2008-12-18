/*
 * Copyright (C) 2008 The Android Open Source Project
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

/* this code is used to generate a boot sequence profile that can be used
 * with the 'bootchart' graphics generation tool. see www.bootchart.org
 * note that unlike the original bootchartd, this is not a Bash script but
 * some C code that is run right from the init script.
 */

#include <stdio.h>
#include <time.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <unistd.h>
#include <fcntl.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>
#include "bootchart.h"

#define VERSION         "0.8"
#define SAMPLE_PERIOD   0.2
#define LOG_ROOT        "/data/bootchart"
#define LOG_STAT        LOG_ROOT"/proc_stat.log"
#define LOG_PROCS       LOG_ROOT"/proc_ps.log"
#define LOG_DISK        LOG_ROOT"/proc_diskstats.log"
#define LOG_HEADER      LOG_ROOT"/header"
#define LOG_ACCT        LOG_ROOT"/kernel_pacct"

#define LOG_STARTFILE   "/data/bootchart-start"
#define LOG_STOPFILE    "/data/bootchart-stop"

static int
unix_read(int  fd, void*  buff, int  len)
{
    int  ret;
    do { ret = read(fd, buff, len); } while (ret < 0 && errno == EINTR);
    return ret;
}

static int
unix_write(int  fd, const void*  buff, int  len)
{
    int  ret;
    do { ret = write(fd, buff, len); } while (ret < 0 && errno == EINTR);
    return ret;
}

static int
proc_read(const char*  filename, char* buff, size_t  buffsize)
{
    int  len = 0;
    int  fd  = open(filename, O_RDONLY);
    if (fd >= 0) {
        len = unix_read(fd, buff, buffsize-1);
        close(fd);
    }
    buff[len > 0 ? len : 0] = 0;
    return len;
}

#define FILE_BUFF_SIZE    65536

typedef struct {
    int   count;
    int   fd;
    char  data[FILE_BUFF_SIZE];
} FileBuffRec, *FileBuff;

static void
file_buff_open( FileBuff  buff, const char*  path )
{
    buff->count = 0;
    buff->fd    = open(path, O_WRONLY|O_CREAT|O_TRUNC, 0755);
}

static void
file_buff_write( FileBuff  buff, const void*  src, int  len )
{
    while (len > 0) {
        int  avail = sizeof(buff->data) - buff->count;
        if (avail > len)
            avail = len;

        memcpy( buff->data + buff->count, src, avail );
        len -= avail;
        src  = (char*)src + avail;

        buff->count += avail;
        if (buff->count == FILE_BUFF_SIZE) {
            unix_write( buff->fd, buff->data, buff->count );
            buff->count = 0;
        }
    }
}

static void
file_buff_done( FileBuff  buff )
{
    if (buff->count > 0) {
        unix_write( buff->fd, buff->data, buff->count );
        buff->count = 0;
    }
}

static void
log_header(void)
{
    FILE*      out;
    char       cmdline[1024];
    char       uname[128];
    char       cpuinfo[128];
    char*      cpu;
    char       date[32];
    time_t     now_t = time(NULL);
    struct tm  now = *localtime(&now_t);
    strftime(date, sizeof(date), "%x %X", &now);

    out = fopen( LOG_HEADER, "w" );
    if (out == NULL)
        return;

    proc_read("/proc/cmdline", cmdline, sizeof(cmdline));
    proc_read("/proc/version", uname, sizeof(uname));
    proc_read("/proc/cpuinfo", cpuinfo, sizeof(cpuinfo));

    cpu = strchr( cpuinfo, ':' );
    if (cpu) {
        char*  p = strchr(cpu, '\n');
        cpu += 2;
        if (p)
            *p = 0;
    }

    fprintf(out, "version = %s\n", VERSION);
    fprintf(out, "title = Boot chart for Android ( %s )\n", date);
    fprintf(out, "system.uname = %s\n", uname);
    fprintf(out, "system.release = 0.0\n");
    fprintf(out, "system.cpu = %s\n", cpu);
    fprintf(out, "system.kernel.options = %s\n", cmdline);
    fclose(out);
}

static void
close_on_exec(int  fd)
{
    fcntl(fd, F_SETFD, FD_CLOEXEC);
}

static void
open_log_file(int*  plogfd, const char*  logfile)
{
    int    logfd = *plogfd;

    /* create log file if needed */
    if (logfd < 0) 
    {
        logfd = open(logfile,O_WRONLY|O_CREAT|O_TRUNC,0755);
        if (logfd < 0) {
            *plogfd = -2;
            return;
        }
        close_on_exec(logfd);
        *plogfd = logfd;
    }
}

static void
do_log_uptime(FileBuff  log)
{
    char  buff[65];
    int   fd, ret, len;

    fd = open("/proc/uptime",O_RDONLY);
    if (fd >= 0) {
        int  ret;
        ret = unix_read(fd, buff, 64);
        close(fd);
        buff[64] = 0;
        if (ret >= 0) {
            long long  jiffies = 100LL*strtod(buff,NULL);
            int        len;
            snprintf(buff,sizeof(buff),"%lld\n",jiffies);
            len = strlen(buff);
            file_buff_write(log, buff, len);
        }
    }
}

static void
do_log_ln(FileBuff  log)
{
    file_buff_write(log, "\n", 1);
}


static void
do_log_file(FileBuff  log, const char*  procfile)
{
    char   buff[1024];
    int    fd;

    do_log_uptime(log);

    /* append file content */
    fd = open(procfile,O_RDONLY);
    if (fd >= 0) {
        close_on_exec(fd);
        for (;;) {
            int  ret;
            ret = unix_read(fd, buff, sizeof(buff));
            if (ret <= 0)
                break;

            file_buff_write(log, buff, ret);
            if (ret < (int)sizeof(buff))
                break;
        }
        close(fd);
    }

    do_log_ln(log);
}

static void
do_log_procs(FileBuff  log)
{
    DIR*  dir = opendir("/proc");
    struct dirent*  entry;

    do_log_uptime(log);

    while ((entry = readdir(dir)) != NULL) {
        /* only match numeric values */
        char*  end;
        int    pid = strtol( entry->d_name, &end, 10);
        if (end != NULL && end > entry->d_name && *end == 0) {
            char  filename[32];
            char  buff[1024];
            char  cmdline[1024];
            int   len;
            int   fd;

            /* read command line and extract program name */
            snprintf(filename,sizeof(filename),"/proc/%d/cmdline",pid);
            proc_read(filename, cmdline, sizeof(cmdline));

            /* read process stat line */
            snprintf(filename,sizeof(filename),"/proc/%d/stat",pid);
            fd = open(filename,O_RDONLY);
            if (fd >= 0) {
               len = unix_read(fd, buff, sizeof(buff)-1);
               close(fd);
               if (len > 0) {
                    int  len2 = strlen(cmdline);
                    if (len2 > 0) {
                        /* we want to substitute the process name with its real name */
                        const char*  p1;
                        const char*  p2;
                        buff[len] = 0;
                        p1 = strchr(buff, '(');
                        p2 = strchr(p1, ')');
                        file_buff_write(log, buff, p1+1-buff);
                        file_buff_write(log, cmdline, strlen(cmdline));
                        file_buff_write(log, p2, strlen(p2));
                    } else {
                        /* no substitution */
                        file_buff_write(log,buff,len);
                    }
               }
            }
        }
    }
    closedir(dir);
    do_log_ln(log);
}

static FileBuffRec  log_stat[1];
static FileBuffRec  log_procs[1];
static FileBuffRec  log_disks[1];

/* called to setup bootcharting */
int   bootchart_init( void )
{
    int  ret;
    char buff[4];
    int  timeout = 0, count = 0;

    buff[0] = 0;
    proc_read( LOG_STARTFILE, buff, sizeof(buff) );
    if (buff[0] != 0) {
        timeout = atoi(buff);
    }
    else {
        /* when running with emulator, androidboot.bootchart=<timeout>
         * might be passed by as kernel parameters to specify the bootchart
         * timeout. this is useful when using -wipe-data since the /data
         * partition is fresh
         */
        char  cmdline[1024];
        char* s;
#define  KERNEL_OPTION  "androidboot.bootchart="
        proc_read( "/proc/cmdline", cmdline, sizeof(cmdline) );
        s = strstr(cmdline, KERNEL_OPTION);
        if (s) {
            s      += sizeof(KERNEL_OPTION)-1;
            timeout = atoi(s);
        }
    }
    if (timeout == 0)
        return 0;

    if (timeout > BOOTCHART_MAX_TIME_SEC)
        timeout = BOOTCHART_MAX_TIME_SEC;

    count = (timeout*1000 + BOOTCHART_POLLING_MS-1)/BOOTCHART_POLLING_MS;

    do {ret=mkdir(LOG_ROOT,0755);}while (ret < 0 && errno == EINTR);

    file_buff_open(log_stat,  LOG_STAT);
    file_buff_open(log_procs, LOG_PROCS);
    file_buff_open(log_disks, LOG_DISK);

    /* create kernel process accounting file */
    {
        int  fd = open( LOG_ACCT, O_WRONLY|O_CREAT|O_TRUNC,0644);
        if (fd >= 0) {
            close(fd);
            acct( LOG_ACCT );
        }
    }

    log_header();
    return count;
}

/* called each time you want to perform a bootchart sampling op */
int  bootchart_step( void )
{
    do_log_file(log_stat,   "/proc/stat");
    do_log_file(log_disks,  "/proc/diskstats");
    do_log_procs(log_procs);

    /* we stop when /data/bootchart-stop contains 1 */
    {
        char  buff[2];
        if (proc_read(LOG_STOPFILE,buff,sizeof(buff)) > 0 && buff[0] == '1') {
            return -1;
        }
    }

    return 0;
}

void  bootchart_finish( void )
{
    unlink( LOG_STOPFILE );
    file_buff_done(log_stat);
    file_buff_done(log_disks);
    file_buff_done(log_procs);
    acct(NULL);
}

/*
 * Copyright (C) 2007 The Android Open Source Project
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <limits.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <assert.h>

#include "sysdeps.h"

#ifdef HAVE_TERMIO_H
#include <termios.h>
#endif

#define  TRACE_TAG  TRACE_ADB
#include "adb.h"
#include "adb_client.h"
#include "file_sync_service.h"

static int do_cmd(transport_type ttype, char* serial, char *cmd, ...);

void get_my_path(char *s, size_t maxLen);
int find_sync_dirs(const char *srcarg,
        char **android_srcdir_out, char **data_srcdir_out);
int install_app(transport_type transport, char* serial, int argc, char** argv);
int uninstall_app(transport_type transport, char* serial, int argc, char** argv);

static const char *gProductOutPath = NULL;
extern int gListenAll;

static char *product_file(const char *extra)
{
    int n;
    char *x;

    if (gProductOutPath == NULL) {
        fprintf(stderr, "adb: Product directory not specified; "
                "use -p or define ANDROID_PRODUCT_OUT\n");
        exit(1);
    }

    n = strlen(gProductOutPath) + strlen(extra) + 2;
    x = malloc(n);
    if (x == 0) {
        fprintf(stderr, "adb: Out of memory (product_file())\n");
        exit(1);
    }

    snprintf(x, (size_t)n, "%s" OS_PATH_SEPARATOR_STR "%s", gProductOutPath, extra);
    return x;
}

void version(FILE * out) {
    fprintf(out, "Android Debug Bridge version %d.%d.%d\n",
         ADB_VERSION_MAJOR, ADB_VERSION_MINOR, ADB_SERVER_VERSION);
}

void help()
{
    version(stderr);

    fprintf(stderr,
        "\n"
        " -a                            - directs adb to listen on all interfaces for a connection\n"
        " -d                            - directs command to the only connected USB device\n"
        "                                 returns an error if more than one USB device is present.\n"
        " -e                            - directs command to the only running emulator.\n"
        "                                 returns an error if more than one emulator is running.\n"
        " -s <specific device>          - directs command to the device or emulator with the given\n"
        "                                 serial number or qualifier. Overrides ANDROID_SERIAL\n"
        "                                 environment variable.\n"
        " -p <product name or path>     - simple product name like 'sooner', or\n"
        "                                 a relative/absolute path to a product\n"
        "                                 out directory like 'out/target/product/sooner'.\n"
        "                                 If -p is not specified, the ANDROID_PRODUCT_OUT\n"
        "                                 environment variable is used, which must\n"
        "                                 be an absolute path.\n"
        " -H                            - Name of adb server host (default: localhost)\n"
        " -P                            - Port of adb server (default: 5037)\n"
        " devices [-l]                  - list all connected devices\n"
        "                                 ('-l' will also list device qualifiers)\n"
        " connect <host>[:<port>]       - connect to a device via TCP/IP\n"
        "                                 Port 5555 is used by default if no port number is specified.\n"
        " disconnect [<host>[:<port>]]  - disconnect from a TCP/IP device.\n"
        "                                 Port 5555 is used by default if no port number is specified.\n"
        "                                 Using this command with no additional arguments\n"
        "                                 will disconnect from all connected TCP/IP devices.\n"
        "\n"
        "device commands:\n"
        "  adb push <local> <remote>    - copy file/dir to device\n"
        "  adb pull <remote> [<local>]  - copy file/dir from device\n"
        "  adb sync [ <directory> ]     - copy host->device only if changed\n"
        "                                 (-l means list but don't copy)\n"
        "                                 (see 'adb help all')\n"
        "  adb shell                    - run remote shell interactively\n"
        "  adb shell <command>          - run remote shell command\n"
        "  adb emu <command>            - run emulator console command\n"
        "  adb logcat [ <filter-spec> ] - View device log\n"
        "  adb forward --list           - list all forward socket connections.\n"
        "                                 the format is a list of lines with the following format:\n"
        "                                    <serial> \" \" <local> \" \" <remote> \"\\n\"\n"
        "  adb forward <local> <remote> - forward socket connections\n"
        "                                 forward specs are one of: \n"
        "                                   tcp:<port>\n"
        "                                   localabstract:<unix domain socket name>\n"
        "                                   localreserved:<unix domain socket name>\n"
        "                                   localfilesystem:<unix domain socket name>\n"
        "                                   dev:<character device name>\n"
        "                                   jdwp:<process pid> (remote only)\n"
        "  adb forward --no-rebind <local> <remote>\n"
        "                               - same as 'adb forward <local> <remote>' but fails\n"
        "                                 if <local> is already forwarded\n"
        "  adb forward --remove <local> - remove a specific forward socket connection\n"
        "  adb forward --remove-all     - remove all forward socket connections\n"
        "  adb jdwp                     - list PIDs of processes hosting a JDWP transport\n"
        "  adb install [-l] [-r] [-s] [--algo <algorithm name> --key <hex-encoded key> --iv <hex-encoded iv>] <file>\n"
        "                               - push this package file to the device and install it\n"
        "                                 ('-l' means forward-lock the app)\n"
        "                                 ('-r' means reinstall the app, keeping its data)\n"
        "                                 ('-s' means install on SD card instead of internal storage)\n"
        "                                 ('--algo', '--key', and '--iv' mean the file is encrypted already)\n"
        "  adb uninstall [-k] <package> - remove this app package from the device\n"
        "                                 ('-k' means keep the data and cache directories)\n"
        "  adb bugreport                - return all information from the device\n"
        "                                 that should be included in a bug report.\n"
        "\n"
        "  adb backup [-f <file>] [-apk|-noapk] [-shared|-noshared] [-all] [-system|-nosystem] [<packages...>]\n"
        "                               - write an archive of the device's data to <file>.\n"
        "                                 If no -f option is supplied then the data is written\n"
        "                                 to \"backup.ab\" in the current directory.\n"
        "                                 (-apk|-noapk enable/disable backup of the .apks themselves\n"
        "                                    in the archive; the default is noapk.)\n"
        "                                 (-shared|-noshared enable/disable backup of the device's\n"
        "                                    shared storage / SD card contents; the default is noshared.)\n"
        "                                 (-all means to back up all installed applications)\n"
        "                                 (-system|-nosystem toggles whether -all automatically includes\n"
        "                                    system applications; the default is to include system apps)\n"
        "                                 (<packages...> is the list of applications to be backed up.  If\n"
        "                                    the -all or -shared flags are passed, then the package\n"
        "                                    list is optional.  Applications explicitly given on the\n"
        "                                    command line will be included even if -nosystem would\n"
        "                                    ordinarily cause them to be omitted.)\n"
        "\n"
        "  adb restore <file>           - restore device contents from the <file> backup archive\n"
        "\n"
        "  adb help                     - show this help message\n"
        "  adb version                  - show version num\n"
        "\n"
        "scripting:\n"
        "  adb wait-for-device          - block until device is online\n"
        "  adb start-server             - ensure that there is a server running\n"
        "  adb kill-server              - kill the server if it is running\n"
        "  adb get-state                - prints: offline | bootloader | device\n"
        "  adb get-serialno             - prints: <serial-number>\n"
        "  adb get-devpath              - prints: <device-path>\n"
        "  adb status-window            - continuously print device status for a specified device\n"
        "  adb remount                  - remounts the /system partition on the device read-write\n"
        "  adb reboot [bootloader|recovery] - reboots the device, optionally into the bootloader or recovery program\n"
        "  adb reboot-bootloader        - reboots the device into the bootloader\n"
        "  adb root                     - restarts the adbd daemon with root permissions\n"
        "  adb usb                      - restarts the adbd daemon listening on USB\n"
        "  adb tcpip <port>             - restarts the adbd daemon listening on TCP on the specified port"
        "\n"
        "networking:\n"
        "  adb ppp <tty> [parameters]   - Run PPP over USB.\n"
        " Note: you should not automatically start a PPP connection.\n"
        " <tty> refers to the tty for PPP stream. Eg. dev:/dev/omap_csmi_tty1\n"
        " [parameters] - Eg. defaultroute debug dump local notty usepeerdns\n"
        "\n"
        "adb sync notes: adb sync [ <directory> ]\n"
        "  <localdir> can be interpreted in several ways:\n"
        "\n"
        "  - If <directory> is not specified, both /system and /data partitions will be updated.\n"
        "\n"
        "  - If it is \"system\" or \"data\", only the corresponding partition\n"
        "    is updated.\n"
        "\n"
        "environmental variables:\n"
        "  ADB_TRACE                    - Print debug information. A comma separated list of the following values\n"
        "                                 1 or all, adb, sockets, packets, rwx, usb, sync, sysdeps, transport, jdwp\n"
        "  ANDROID_SERIAL               - The serial number to connect to. -s takes priority over this if given.\n"
        "  ANDROID_LOG_TAGS             - When used with the logcat option, only these debug tags are printed.\n"
        );
}

int usage()
{
    help();
    return 1;
}

#ifdef HAVE_TERMIO_H
static struct termios tio_save;

static void stdin_raw_init(int fd)
{
    struct termios tio;

    if(tcgetattr(fd, &tio)) return;
    if(tcgetattr(fd, &tio_save)) return;

    tio.c_lflag = 0; /* disable CANON, ECHO*, etc */

        /* no timeout but request at least one character per read */
    tio.c_cc[VTIME] = 0;
    tio.c_cc[VMIN] = 1;

    tcsetattr(fd, TCSANOW, &tio);
    tcflush(fd, TCIFLUSH);
}

static void stdin_raw_restore(int fd)
{
    tcsetattr(fd, TCSANOW, &tio_save);
    tcflush(fd, TCIFLUSH);
}
#endif

static void read_and_dump(int fd)
{
    char buf[4096];
    int len;

    while(fd >= 0) {
        D("read_and_dump(): pre adb_read(fd=%d)\n", fd);
        len = adb_read(fd, buf, 4096);
        D("read_and_dump(): post adb_read(fd=%d): len=%d\n", fd, len);
        if(len == 0) {
            break;
        }

        if(len < 0) {
            if(errno == EINTR) continue;
            break;
        }
        fwrite(buf, 1, len, stdout);
        fflush(stdout);
    }
}

static void copy_to_file(int inFd, int outFd) {
    const size_t BUFSIZE = 32 * 1024;
    char* buf = (char*) malloc(BUFSIZE);
    int len;
    long total = 0;

    D("copy_to_file(%d -> %d)\n", inFd, outFd);
    for (;;) {
        len = adb_read(inFd, buf, BUFSIZE);
        if (len == 0) {
            D("copy_to_file() : read 0 bytes; exiting\n");
            break;
        }
        if (len < 0) {
            if (errno == EINTR) {
                D("copy_to_file() : EINTR, retrying\n");
                continue;
            }
            D("copy_to_file() : error %d\n", errno);
            break;
        }
        adb_write(outFd, buf, len);
        total += len;
    }
    D("copy_to_file() finished after %lu bytes\n", total);
    free(buf);
}

static void *stdin_read_thread(void *x)
{
    int fd, fdi;
    unsigned char buf[1024];
    int r, n;
    int state = 0;

    int *fds = (int*) x;
    fd = fds[0];
    fdi = fds[1];
    free(fds);

    for(;;) {
        /* fdi is really the client's stdin, so use read, not adb_read here */
        D("stdin_read_thread(): pre unix_read(fdi=%d,...)\n", fdi);
        r = unix_read(fdi, buf, 1024);
        D("stdin_read_thread(): post unix_read(fdi=%d,...)\n", fdi);
        if(r == 0) break;
        if(r < 0) {
            if(errno == EINTR) continue;
            break;
        }
        for(n = 0; n < r; n++){
            switch(buf[n]) {
            case '\n':
                state = 1;
                break;
            case '\r':
                state = 1;
                break;
            case '~':
                if(state == 1) state++;
                break;
            case '.':
                if(state == 2) {
                    fprintf(stderr,"\n* disconnect *\n");
#ifdef HAVE_TERMIO_H
                    stdin_raw_restore(fdi);
#endif
                    exit(0);
                }
            default:
                state = 0;
            }
        }
        r = adb_write(fd, buf, r);
        if(r <= 0) {
            break;
        }
    }
    return 0;
}

int interactive_shell(void)
{
    adb_thread_t thr;
    int fdi, fd;
    int *fds;

    fd = adb_connect("shell:");
    if(fd < 0) {
        fprintf(stderr,"error: %s\n", adb_error());
        return 1;
    }
    fdi = 0; //dup(0);

    fds = malloc(sizeof(int) * 2);
    fds[0] = fd;
    fds[1] = fdi;

#ifdef HAVE_TERMIO_H
    stdin_raw_init(fdi);
#endif
    adb_thread_create(&thr, stdin_read_thread, fds);
    read_and_dump(fd);
#ifdef HAVE_TERMIO_H
    stdin_raw_restore(fdi);
#endif
    return 0;
}


static void format_host_command(char* buffer, size_t  buflen, const char* command, transport_type ttype, const char* serial)
{
    if (serial) {
        snprintf(buffer, buflen, "host-serial:%s:%s", serial, command);
    } else {
        const char* prefix = "host";
        if (ttype == kTransportUsb)
            prefix = "host-usb";
        else if (ttype == kTransportLocal)
            prefix = "host-local";

        snprintf(buffer, buflen, "%s:%s", prefix, command);
    }
}

int adb_download_buffer(const char *service, const void* data, int sz,
                        unsigned progress)
{
    char buf[4096];
    unsigned total;
    int fd;
    const unsigned char *ptr;

    sprintf(buf,"%s:%d", service, sz);
    fd = adb_connect(buf);
    if(fd < 0) {
        fprintf(stderr,"error: %s\n", adb_error());
        return -1;
    }

    int opt = CHUNK_SIZE;
    opt = setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &opt, sizeof(opt));

    total = sz;
    ptr = data;

    if(progress) {
        char *x = strrchr(service, ':');
        if(x) service = x + 1;
    }

    while(sz > 0) {
        unsigned xfer = (sz > CHUNK_SIZE) ? CHUNK_SIZE : sz;
        if(writex(fd, ptr, xfer)) {
            adb_status(fd);
            fprintf(stderr,"* failed to write data '%s' *\n", adb_error());
            return -1;
        }
        sz -= xfer;
        ptr += xfer;
        if(progress) {
            printf("sending: '%s' %4d%%    \r", service, (int)(100LL - ((100LL * sz) / (total))));
            fflush(stdout);
        }
    }
    if(progress) {
        printf("\n");
    }

    if(readx(fd, buf, 4)){
        fprintf(stderr,"* error reading response *\n");
        adb_close(fd);
        return -1;
    }
    if(memcmp(buf, "OKAY", 4)) {
        buf[4] = 0;
        fprintf(stderr,"* error response '%s' *\n", buf);
        adb_close(fd);
        return -1;
    }

    adb_close(fd);
    return 0;
}


int adb_download(const char *service, const char *fn, unsigned progress)
{
    void *data;
    unsigned sz;

    data = load_file(fn, &sz);
    if(data == 0) {
        fprintf(stderr,"* cannot read '%s' *\n", service);
        return -1;
    }

    int status = adb_download_buffer(service, data, sz, progress);
    free(data);
    return status;
}

static void status_window(transport_type ttype, const char* serial)
{
    char command[4096];
    char *state = 0;
    char *laststate = 0;

        /* silence stderr */
#ifdef _WIN32
    /* XXX: TODO */
#else
    int  fd;
    fd = unix_open("/dev/null", O_WRONLY);
    dup2(fd, 2);
    adb_close(fd);
#endif

    format_host_command(command, sizeof command, "get-state", ttype, serial);

    for(;;) {
        adb_sleep_ms(250);

        if(state) {
            free(state);
            state = 0;
        }

        state = adb_query(command);

        if(state) {
            if(laststate && !strcmp(state,laststate)){
                continue;
            } else {
                if(laststate) free(laststate);
                laststate = strdup(state);
            }
        }

        printf("%c[2J%c[2H", 27, 27);
        printf("Android Debug Bridge\n");
        printf("State: %s\n", state ? state : "offline");
        fflush(stdout);
    }
}

/** duplicate string and quote all \ " ( ) chars + space character. */
static char *
dupAndQuote(const char *s)
{
    const char *ts;
    size_t alloc_len;
    char *ret;
    char *dest;

    ts = s;

    alloc_len = 0;

    for( ;*ts != '\0'; ts++) {
        alloc_len++;
        if (*ts == ' ' || *ts == '"' || *ts == '\\' || *ts == '(' || *ts == ')') {
            alloc_len++;
        }
    }

    ret = (char *)malloc(alloc_len + 1);

    ts = s;
    dest = ret;

    for ( ;*ts != '\0'; ts++) {
        if (*ts == ' ' || *ts == '"' || *ts == '\\' || *ts == '(' || *ts == ')') {
            *dest++ = '\\';
        }

        *dest++ = *ts;
    }

    *dest++ = '\0';

    return ret;
}

/**
 * Run ppp in "notty" mode against a resource listed as the first parameter
 * eg:
 *
 * ppp dev:/dev/omap_csmi_tty0 <ppp options>
 *
 */
int ppp(int argc, char **argv)
{
#ifdef HAVE_WIN32_PROC
    fprintf(stderr, "error: adb %s not implemented on Win32\n", argv[0]);
    return -1;
#else
    char *adb_service_name;
    pid_t pid;
    int fd;

    if (argc < 2) {
        fprintf(stderr, "usage: adb %s <adb service name> [ppp opts]\n",
                argv[0]);

        return 1;
    }

    adb_service_name = argv[1];

    fd = adb_connect(adb_service_name);

    if(fd < 0) {
        fprintf(stderr,"Error: Could not open adb service: %s. Error: %s\n",
                adb_service_name, adb_error());
        return 1;
    }

    pid = fork();

    if (pid < 0) {
        perror("from fork()");
        return 1;
    } else if (pid == 0) {
        int err;
        int i;
        const char **ppp_args;

        // copy args
        ppp_args = (const char **) alloca(sizeof(char *) * argc + 1);
        ppp_args[0] = "pppd";
        for (i = 2 ; i < argc ; i++) {
            //argv[2] and beyond become ppp_args[1] and beyond
            ppp_args[i - 1] = argv[i];
        }
        ppp_args[i-1] = NULL;

        // child side

        dup2(fd, STDIN_FILENO);
        dup2(fd, STDOUT_FILENO);
        adb_close(STDERR_FILENO);
        adb_close(fd);

        err = execvp("pppd", (char * const *)ppp_args);

        if (err < 0) {
            perror("execing pppd");
        }
        exit(-1);
    } else {
        // parent side

        adb_close(fd);
        return 0;
    }
#endif /* !HAVE_WIN32_PROC */
}

static int send_shellcommand(transport_type transport, char* serial, char* buf)
{
    int fd, ret;

    for(;;) {
        fd = adb_connect(buf);
        if(fd >= 0)
            break;
        fprintf(stderr,"- waiting for device -\n");
        adb_sleep_ms(1000);
        do_cmd(transport, serial, "wait-for-device", 0);
    }

    read_and_dump(fd);
    ret = adb_close(fd);
    if (ret)
        perror("close");

    return ret;
}

static int logcat(transport_type transport, char* serial, int argc, char **argv)
{
    char buf[4096];

    char *log_tags;
    char *quoted_log_tags;

    log_tags = getenv("ANDROID_LOG_TAGS");
    quoted_log_tags = dupAndQuote(log_tags == NULL ? "" : log_tags);

    snprintf(buf, sizeof(buf),
        "shell:export ANDROID_LOG_TAGS=\"\%s\" ; exec logcat",
        quoted_log_tags);

    free(quoted_log_tags);

    if (!strcmp(argv[0],"longcat")) {
        strncat(buf, " -v long", sizeof(buf)-1);
    }

    argc -= 1;
    argv += 1;
    while(argc-- > 0) {
        char *quoted;

        quoted = dupAndQuote (*argv++);

        strncat(buf, " ", sizeof(buf)-1);
        strncat(buf, quoted, sizeof(buf)-1);
        free(quoted);
    }

    send_shellcommand(transport, serial, buf);
    return 0;
}

static int mkdirs(char *path)
{
    int ret;
    char *x = path + 1;

    for(;;) {
        x = adb_dirstart(x);
        if(x == 0) return 0;
        *x = 0;
        ret = adb_mkdir(path, 0775);
        *x = OS_PATH_SEPARATOR;
        if((ret < 0) && (errno != EEXIST)) {
            return ret;
        }
        x++;
    }
    return 0;
}

static int backup(int argc, char** argv) {
    char buf[4096];
    char default_name[32];
    const char* filename = strcpy(default_name, "./backup.ab");
    int fd, outFd;
    int i, j;

    /* find, extract, and use any -f argument */
    for (i = 1; i < argc; i++) {
        if (!strcmp("-f", argv[i])) {
            if (i == argc-1) {
                fprintf(stderr, "adb: -f passed with no filename\n");
                return usage();
            }
            filename = argv[i+1];
            for (j = i+2; j <= argc; ) {
                argv[i++] = argv[j++];
            }
            argc -= 2;
            argv[argc] = NULL;
        }
    }

    /* bare "adb backup" or "adb backup -f filename" are not valid invocations */
    if (argc < 2) return usage();

    adb_unlink(filename);
    mkdirs((char *)filename);
    outFd = adb_creat(filename, 0640);
    if (outFd < 0) {
        fprintf(stderr, "adb: unable to open file %s\n", filename);
        return -1;
    }

    snprintf(buf, sizeof(buf), "backup");
    for (argc--, argv++; argc; argc--, argv++) {
        strncat(buf, ":", sizeof(buf) - strlen(buf) - 1);
        strncat(buf, argv[0], sizeof(buf) - strlen(buf) - 1);
    }

    D("backup. filename=%s buf=%s\n", filename, buf);
    fd = adb_connect(buf);
    if (fd < 0) {
        fprintf(stderr, "adb: unable to connect for backup\n");
        adb_close(outFd);
        return -1;
    }

    printf("Now unlock your device and confirm the backup operation.\n");
    copy_to_file(fd, outFd);

    adb_close(fd);
    adb_close(outFd);
    return 0;
}

static int restore(int argc, char** argv) {
    const char* filename;
    int fd, tarFd;

    if (argc != 2) return usage();

    filename = argv[1];
    tarFd = adb_open(filename, O_RDONLY);
    if (tarFd < 0) {
        fprintf(stderr, "adb: unable to open file %s\n", filename);
        return -1;
    }

    fd = adb_connect("restore:");
    if (fd < 0) {
        fprintf(stderr, "adb: unable to connect for backup\n");
        adb_close(tarFd);
        return -1;
    }

    printf("Now unlock your device and confirm the restore operation.\n");
    copy_to_file(tarFd, fd);

    adb_close(fd);
    adb_close(tarFd);
    return 0;
}

#define SENTINEL_FILE "config" OS_PATH_SEPARATOR_STR "envsetup.make"
static int top_works(const char *top)
{
    if (top != NULL && adb_is_absolute_host_path(top)) {
        char path_buf[PATH_MAX];
        snprintf(path_buf, sizeof(path_buf),
                "%s" OS_PATH_SEPARATOR_STR SENTINEL_FILE, top);
        return access(path_buf, F_OK) == 0;
    }
    return 0;
}

static char *find_top_from(const char *indir, char path_buf[PATH_MAX])
{
    strcpy(path_buf, indir);
    while (1) {
        if (top_works(path_buf)) {
            return path_buf;
        }
        char *s = adb_dirstop(path_buf);
        if (s != NULL) {
            *s = '\0';
        } else {
            path_buf[0] = '\0';
            return NULL;
        }
    }
}

static char *find_top(char path_buf[PATH_MAX])
{
    char *top = getenv("ANDROID_BUILD_TOP");
    if (top != NULL && top[0] != '\0') {
        if (!top_works(top)) {
            fprintf(stderr, "adb: bad ANDROID_BUILD_TOP value \"%s\"\n", top);
            return NULL;
        }
    } else {
        top = getenv("TOP");
        if (top != NULL && top[0] != '\0') {
            if (!top_works(top)) {
                fprintf(stderr, "adb: bad TOP value \"%s\"\n", top);
                return NULL;
            }
        } else {
            top = NULL;
        }
    }

    if (top != NULL) {
        /* The environment pointed to a top directory that works.
         */
        strcpy(path_buf, top);
        return path_buf;
    }

    /* The environment didn't help.  Walk up the tree from the CWD
     * to see if we can find the top.
     */
    char dir[PATH_MAX];
    top = find_top_from(getcwd(dir, sizeof(dir)), path_buf);
    if (top == NULL) {
        /* If the CWD isn't under a good-looking top, see if the
         * executable is.
         */
        get_my_path(dir, PATH_MAX);
        top = find_top_from(dir, path_buf);
    }
    return top;
}

/* <hint> may be:
 * - A simple product name
 *   e.g., "sooner"
TODO: debug?  sooner-debug, sooner:debug?
 * - A relative path from the CWD to the ANDROID_PRODUCT_OUT dir
 *   e.g., "out/target/product/sooner"
 * - An absolute path to the PRODUCT_OUT dir
 *   e.g., "/src/device/out/target/product/sooner"
 *
 * Given <hint>, try to construct an absolute path to the
 * ANDROID_PRODUCT_OUT dir.
 */
static const char *find_product_out_path(const char *hint)
{
    static char path_buf[PATH_MAX];

    if (hint == NULL || hint[0] == '\0') {
        return NULL;
    }

    /* If it's already absolute, don't bother doing any work.
     */
    if (adb_is_absolute_host_path(hint)) {
        strcpy(path_buf, hint);
        return path_buf;
    }

    /* If there are any slashes in it, assume it's a relative path;
     * make it absolute.
     */
    if (adb_dirstart(hint) != NULL) {
        if (getcwd(path_buf, sizeof(path_buf)) == NULL) {
            fprintf(stderr, "adb: Couldn't get CWD: %s\n", strerror(errno));
            return NULL;
        }
        if (strlen(path_buf) + 1 + strlen(hint) >= sizeof(path_buf)) {
            fprintf(stderr, "adb: Couldn't assemble path\n");
            return NULL;
        }
        strcat(path_buf, OS_PATH_SEPARATOR_STR);
        strcat(path_buf, hint);
        return path_buf;
    }

    /* It's a string without any slashes.  Try to do something with it.
     *
     * Try to find the root of the build tree, and build a PRODUCT_OUT
     * path from there.
     */
    char top_buf[PATH_MAX];
    const char *top = find_top(top_buf);
    if (top == NULL) {
        fprintf(stderr, "adb: Couldn't find top of build tree\n");
        return NULL;
    }
//TODO: if we have a way to indicate debug, look in out/debug/target/...
    snprintf(path_buf, sizeof(path_buf),
            "%s" OS_PATH_SEPARATOR_STR
            "out" OS_PATH_SEPARATOR_STR
            "target" OS_PATH_SEPARATOR_STR
            "product" OS_PATH_SEPARATOR_STR
            "%s", top_buf, hint);
    if (access(path_buf, F_OK) < 0) {
        fprintf(stderr, "adb: Couldn't find a product dir "
                "based on \"-p %s\"; \"%s\" doesn't exist\n", hint, path_buf);
        return NULL;
    }
    return path_buf;
}

int adb_commandline(int argc, char **argv)
{
    char buf[4096];
    int no_daemon = 0;
    int is_daemon = 0;
    int is_server = 0;
    int persist = 0;
    int r;
    int quote;
    transport_type ttype = kTransportAny;
    char* serial = NULL;
    char* server_port_str = NULL;

        /* If defined, this should be an absolute path to
         * the directory containing all of the various system images
         * for a particular product.  If not defined, and the adb
         * command requires this information, then the user must
         * specify the path using "-p".
         */
    gProductOutPath = getenv("ANDROID_PRODUCT_OUT");
    if (gProductOutPath == NULL || gProductOutPath[0] == '\0') {
        gProductOutPath = NULL;
    }
    // TODO: also try TARGET_PRODUCT/TARGET_DEVICE as a hint

    serial = getenv("ANDROID_SERIAL");

    /* Validate and assign the server port */
    server_port_str = getenv("ANDROID_ADB_SERVER_PORT");
    int server_port = DEFAULT_ADB_PORT;
    if (server_port_str && strlen(server_port_str) > 0) {
        server_port = (int) strtol(server_port_str, NULL, 0);
        if (server_port <= 0 || server_port > 65535) {
            fprintf(stderr,
                    "adb: Env var ANDROID_ADB_SERVER_PORT must be a positive number less than 65535. Got \"%s\"\n",
                    server_port_str);
            return usage();
        }
    }

    /* modifiers and flags */
    while(argc > 0) {
        if(!strcmp(argv[0],"server")) {
            is_server = 1;
        } else if(!strcmp(argv[0],"nodaemon")) {
            no_daemon = 1;
        } else if (!strcmp(argv[0], "fork-server")) {
            /* this is a special flag used only when the ADB client launches the ADB Server */
            is_daemon = 1;
        } else if(!strcmp(argv[0],"persist")) {
            persist = 1;
        } else if(!strncmp(argv[0], "-p", 2)) {
            const char *product = NULL;
            if (argv[0][2] == '\0') {
                if (argc < 2) return usage();
                product = argv[1];
                argc--;
                argv++;
            } else {
                product = argv[0] + 2;
            }
            gProductOutPath = find_product_out_path(product);
            if (gProductOutPath == NULL) {
                fprintf(stderr, "adb: could not resolve \"-p %s\"\n",
                        product);
                return usage();
            }
        } else if (argv[0][0]=='-' && argv[0][1]=='s') {
            if (isdigit(argv[0][2])) {
                serial = argv[0] + 2;
            } else {
                if(argc < 2 || argv[0][2] != '\0') return usage();
                serial = argv[1];
                argc--;
                argv++;
            }
        } else if (!strcmp(argv[0],"-d")) {
            ttype = kTransportUsb;
        } else if (!strcmp(argv[0],"-e")) {
            ttype = kTransportLocal;
        } else if (!strcmp(argv[0],"-a")) {
            gListenAll = 1;
        } else if(!strncmp(argv[0], "-H", 2)) {
            const char *hostname = NULL;
            if (argv[0][2] == '\0') {
                if (argc < 2) return usage();
                hostname = argv[1];
                argc--;
                argv++;
            } else {
                hostname = argv[0] + 2;
            }
            adb_set_tcp_name(hostname);

        } else if(!strncmp(argv[0], "-P", 2)) {
            if (argv[0][2] == '\0') {
                if (argc < 2) return usage();
                server_port_str = argv[1];
                argc--;
                argv++;
            } else {
                server_port_str = argv[0] + 2;
            }
            if (strlen(server_port_str) > 0) {
                server_port = (int) strtol(server_port_str, NULL, 0);
                if (server_port <= 0 || server_port > 65535) {
                    fprintf(stderr,
                            "adb: port number must be a positive number less than 65536. Got \"%s\"\n",
                            server_port_str);
                    return usage();
                }
            } else {
                fprintf(stderr,
                "adb: port number must be a positive number less than 65536. Got empty string.\n");
                return usage();
            }
        } else {
                /* out of recognized modifiers and flags */
            break;
        }
        argc--;
        argv++;
    }

    adb_set_transport(ttype, serial);
    adb_set_tcp_specifics(server_port);

    if (is_server) {
        if (no_daemon || is_daemon) {
            r = adb_main(is_daemon, server_port);
        } else {
            r = launch_server(server_port);
        }
        if(r) {
            fprintf(stderr,"* could not start server *\n");
        }
        return r;
    }

top:
    if(argc == 0) {
        return usage();
    }

    /* adb_connect() commands */

    if(!strcmp(argv[0], "devices")) {
        char *tmp;
        char *listopt;
        if (argc < 2)
            listopt = "";
        else if (argc == 2 && !strcmp(argv[1], "-l"))
            listopt = argv[1];
        else {
            fprintf(stderr, "Usage: adb devices [-l]\n");
            return 1;
        }
        snprintf(buf, sizeof buf, "host:%s%s", argv[0], listopt);
        tmp = adb_query(buf);
        if(tmp) {
            printf("List of devices attached \n");
            printf("%s\n", tmp);
            return 0;
        } else {
            return 1;
        }
    }

    if(!strcmp(argv[0], "connect")) {
        char *tmp;
        if (argc != 2) {
            fprintf(stderr, "Usage: adb connect <host>[:<port>]\n");
            return 1;
        }
        snprintf(buf, sizeof buf, "host:connect:%s", argv[1]);
        tmp = adb_query(buf);
        if(tmp) {
            printf("%s\n", tmp);
            return 0;
        } else {
            return 1;
        }
    }

    if(!strcmp(argv[0], "disconnect")) {
        char *tmp;
        if (argc > 2) {
            fprintf(stderr, "Usage: adb disconnect [<host>[:<port>]]\n");
            return 1;
        }
        if (argc == 2) {
            snprintf(buf, sizeof buf, "host:disconnect:%s", argv[1]);
        } else {
            snprintf(buf, sizeof buf, "host:disconnect:");
        }
        tmp = adb_query(buf);
        if(tmp) {
            printf("%s\n", tmp);
            return 0;
        } else {
            return 1;
        }
    }

    if (!strcmp(argv[0], "emu")) {
        return adb_send_emulator_command(argc, argv);
    }

    if(!strcmp(argv[0], "shell") || !strcmp(argv[0], "hell")) {
        int r;
        int fd;

        char h = (argv[0][0] == 'h');

        if (h) {
            printf("\x1b[41;33m");
            fflush(stdout);
        }

        if(argc < 2) {
            D("starting interactive shell\n");
            r = interactive_shell();
            if (h) {
                printf("\x1b[0m");
                fflush(stdout);
            }
            return r;
        }

        snprintf(buf, sizeof buf, "shell:%s", argv[1]);
        argc -= 2;
        argv += 2;
        while(argc-- > 0) {
            strcat(buf, " ");

            /* quote empty strings and strings with spaces */
            quote = (**argv == 0 || strchr(*argv, ' '));
            if (quote)
                strcat(buf, "\"");
            strcat(buf, *argv++);
            if (quote)
                strcat(buf, "\"");
        }

        for(;;) {
            D("interactive shell loop. buff=%s\n", buf);
            fd = adb_connect(buf);
            if(fd >= 0) {
                D("about to read_and_dump(fd=%d)\n", fd);
                read_and_dump(fd);
                D("read_and_dump() done.\n");
                adb_close(fd);
                r = 0;
            } else {
                fprintf(stderr,"error: %s\n", adb_error());
                r = -1;
            }

            if(persist) {
                fprintf(stderr,"\n- waiting for device -\n");
                adb_sleep_ms(1000);
                do_cmd(ttype, serial, "wait-for-device", 0);
            } else {
                if (h) {
                    printf("\x1b[0m");
                    fflush(stdout);
                }
                D("interactive shell loop. return r=%d\n", r);
                return r;
            }
        }
    }

    if(!strcmp(argv[0], "kill-server")) {
        int fd;
        fd = _adb_connect("host:kill");
        if(fd == -1) {
            fprintf(stderr,"* server not running *\n");
            return 1;
        }
        return 0;
    }

    if(!strcmp(argv[0], "sideload")) {
        if(argc != 2) return usage();
        if(adb_download("sideload", argv[1], 1)) {
            return 1;
        } else {
            return 0;
        }
    }

    if(!strcmp(argv[0], "remount") || !strcmp(argv[0], "reboot")
            || !strcmp(argv[0], "reboot-bootloader")
            || !strcmp(argv[0], "tcpip") || !strcmp(argv[0], "usb")
            || !strcmp(argv[0], "root")) {
        char command[100];
        if (!strcmp(argv[0], "reboot-bootloader"))
            snprintf(command, sizeof(command), "reboot:bootloader");
        else if (argc > 1)
            snprintf(command, sizeof(command), "%s:%s", argv[0], argv[1]);
        else
            snprintf(command, sizeof(command), "%s:", argv[0]);
        int fd = adb_connect(command);
        if(fd >= 0) {
            read_and_dump(fd);
            adb_close(fd);
            return 0;
        }
        fprintf(stderr,"error: %s\n", adb_error());
        return 1;
    }

    if(!strcmp(argv[0], "bugreport")) {
        if (argc != 1) return usage();
        do_cmd(ttype, serial, "shell", "bugreport", 0);
        return 0;
    }

    /* adb_command() wrapper commands */

    if(!strncmp(argv[0], "wait-for-", strlen("wait-for-"))) {
        char* service = argv[0];
        if (!strncmp(service, "wait-for-device", strlen("wait-for-device"))) {
            if (ttype == kTransportUsb) {
                service = "wait-for-usb";
            } else if (ttype == kTransportLocal) {
                service = "wait-for-local";
            } else {
                service = "wait-for-any";
            }
        }

        format_host_command(buf, sizeof buf, service, ttype, serial);

        if (adb_command(buf)) {
            D("failure: %s *\n",adb_error());
            fprintf(stderr,"error: %s\n", adb_error());
            return 1;
        }

        /* Allow a command to be run after wait-for-device,
            * e.g. 'adb wait-for-device shell'.
            */
        if(argc > 1) {
            argc--;
            argv++;
            goto top;
        }
        return 0;
    }

    if(!strcmp(argv[0], "forward")) {
        char host_prefix[64];
        char remove = 0;
        char remove_all = 0;
        char list = 0;
        char no_rebind = 0;

        // Parse options here.
        while (argc > 1 && argv[1][0] == '-') {
            if (!strcmp(argv[1], "--list"))
                list = 1;
            else if (!strcmp(argv[1], "--remove"))
                remove = 1;
            else if (!strcmp(argv[1], "--remove-all"))
                remove_all = 1;
            else if (!strcmp(argv[1], "--no-rebind"))
                no_rebind = 1;
            else {
                return usage();
            }
            argc--;
            argv++;
        }

        // Ensure we can only use one option at a time.
        if (list + remove + remove_all + no_rebind > 1) {
            return usage();
        }

        // Determine the <host-prefix> for this command.
        if (serial) {
            snprintf(host_prefix, sizeof host_prefix, "host-serial:%s",
                    serial);
        } else if (ttype == kTransportUsb) {
            snprintf(host_prefix, sizeof host_prefix, "host-usb");
        } else if (ttype == kTransportLocal) {
            snprintf(host_prefix, sizeof host_prefix, "host-local");
        } else {
            snprintf(host_prefix, sizeof host_prefix, "host");
        }

        // Implement forward --list
        if (list) {
            if (argc != 1)
                return usage();
            snprintf(buf, sizeof buf, "%s:list-forward", host_prefix);
            char* forwards = adb_query(buf);
            if (forwards == NULL) {
                fprintf(stderr, "error: %s\n", adb_error());
                return 1;
            }
            printf("%s", forwards);
            free(forwards);
            return 0;
        }

        // Implement forward --remove-all
        else if (remove_all) {
            if (argc != 1)
                return usage();
            snprintf(buf, sizeof buf, "%s:killforward-all", host_prefix);
        }

        // Implement forward --remove <local>
        else if (remove) {
            if (argc != 2)
                return usage();
            snprintf(buf, sizeof buf, "%s:killforward:%s", host_prefix, argv[1]);
        }
        // Or implement one of:
        //    forward <local> <remote>
        //    forward --no-rebind <local> <remote>
        else
        {
          if (argc != 3)
            return usage();
          const char* command = no_rebind ? "forward:norebind:" : "forward";
          snprintf(buf, sizeof buf, "%s:%s:%s;%s", host_prefix, command, argv[1], argv[2]);
        }

        if(adb_command(buf)) {
            fprintf(stderr,"error: %s\n", adb_error());
            return 1;
        }
        return 0;
    }

    /* do_sync_*() commands */

    if(!strcmp(argv[0], "ls")) {
        if(argc != 2) return usage();
        return do_sync_ls(argv[1]);
    }

    if(!strcmp(argv[0], "push")) {
        if(argc != 3) return usage();
        return do_sync_push(argv[1], argv[2], 0 /* no verify APK */);
    }

    if(!strcmp(argv[0], "pull")) {
        if (argc == 2) {
            return do_sync_pull(argv[1], ".");
        } else if (argc == 3) {
            return do_sync_pull(argv[1], argv[2]);
        } else {
            return usage();
        }
    }

    if(!strcmp(argv[0], "install")) {
        if (argc < 2) return usage();
        return install_app(ttype, serial, argc, argv);
    }

    if(!strcmp(argv[0], "uninstall")) {
        if (argc < 2) return usage();
        return uninstall_app(ttype, serial, argc, argv);
    }

    if(!strcmp(argv[0], "sync")) {
        char *srcarg, *android_srcpath, *data_srcpath;
        int listonly = 0;

        int ret;
        if(argc < 2) {
            /* No local path was specified. */
            srcarg = NULL;
        } else if (argc >= 2 && strcmp(argv[1], "-l") == 0) {
            listonly = 1;
            if (argc == 3) {
                srcarg = argv[2];
            } else {
                srcarg = NULL;
            }
        } else if(argc == 2) {
            /* A local path or "android"/"data" arg was specified. */
            srcarg = argv[1];
        } else {
            return usage();
        }
        ret = find_sync_dirs(srcarg, &android_srcpath, &data_srcpath);
        if(ret != 0) return usage();

        if(android_srcpath != NULL)
            ret = do_sync_sync(android_srcpath, "/system", listonly);
        if(ret == 0 && data_srcpath != NULL)
            ret = do_sync_sync(data_srcpath, "/data", listonly);

        free(android_srcpath);
        free(data_srcpath);
        return ret;
    }

    /* passthrough commands */

    if(!strcmp(argv[0],"get-state") ||
        !strcmp(argv[0],"get-serialno") ||
        !strcmp(argv[0],"get-devpath"))
    {
        char *tmp;

        format_host_command(buf, sizeof buf, argv[0], ttype, serial);
        tmp = adb_query(buf);
        if(tmp) {
            printf("%s\n", tmp);
            return 0;
        } else {
            return 1;
        }
    }

    /* other commands */

    if(!strcmp(argv[0],"status-window")) {
        status_window(ttype, serial);
        return 0;
    }

    if(!strcmp(argv[0],"logcat") || !strcmp(argv[0],"lolcat") || !strcmp(argv[0],"longcat")) {
        return logcat(ttype, serial, argc, argv);
    }

    if(!strcmp(argv[0],"ppp")) {
        return ppp(argc, argv);
    }

    if (!strcmp(argv[0], "start-server")) {
        return adb_connect("host:start-server");
    }

    if (!strcmp(argv[0], "backup")) {
        return backup(argc, argv);
    }

    if (!strcmp(argv[0], "restore")) {
        return restore(argc, argv);
    }

    if (!strcmp(argv[0], "jdwp")) {
        int  fd = adb_connect("jdwp");
        if (fd >= 0) {
            read_and_dump(fd);
            adb_close(fd);
            return 0;
        } else {
            fprintf(stderr, "error: %s\n", adb_error());
            return -1;
        }
    }

    /* "adb /?" is a common idiom under Windows */
    if(!strcmp(argv[0], "help") || !strcmp(argv[0], "/?")) {
        help();
        return 0;
    }

    if(!strcmp(argv[0], "version")) {
        version(stdout);
        return 0;
    }

    usage();
    return 1;
}

static int do_cmd(transport_type ttype, char* serial, char *cmd, ...)
{
    char *argv[16];
    int argc;
    va_list ap;

    va_start(ap, cmd);
    argc = 0;

    if (serial) {
        argv[argc++] = "-s";
        argv[argc++] = serial;
    } else if (ttype == kTransportUsb) {
        argv[argc++] = "-d";
    } else if (ttype == kTransportLocal) {
        argv[argc++] = "-e";
    }

    argv[argc++] = cmd;
    while((argv[argc] = va_arg(ap, char*)) != 0) argc++;
    va_end(ap);

#if 0
    int n;
    fprintf(stderr,"argc = %d\n",argc);
    for(n = 0; n < argc; n++) {
        fprintf(stderr,"argv[%d] = \"%s\"\n", n, argv[n]);
    }
#endif

    return adb_commandline(argc, argv);
}

int find_sync_dirs(const char *srcarg,
        char **android_srcdir_out, char **data_srcdir_out)
{
    char *android_srcdir, *data_srcdir;

    if(srcarg == NULL) {
        android_srcdir = product_file("system");
        data_srcdir = product_file("data");
    } else {
        /* srcarg may be "data", "system" or NULL.
         * if srcarg is NULL, then both data and system are synced
         */
        if(strcmp(srcarg, "system") == 0) {
            android_srcdir = product_file("system");
            data_srcdir = NULL;
        } else if(strcmp(srcarg, "data") == 0) {
            android_srcdir = NULL;
            data_srcdir = product_file("data");
        } else {
            /* It's not "system" or "data".
             */
            return 1;
        }
    }

    if(android_srcdir_out != NULL)
        *android_srcdir_out = android_srcdir;
    else
        free(android_srcdir);

    if(data_srcdir_out != NULL)
        *data_srcdir_out = data_srcdir;
    else
        free(data_srcdir);

    return 0;
}

static int pm_command(transport_type transport, char* serial,
                      int argc, char** argv)
{
    char buf[4096];

    snprintf(buf, sizeof(buf), "shell:pm");

    while(argc-- > 0) {
        char *quoted;

        quoted = dupAndQuote(*argv++);

        strncat(buf, " ", sizeof(buf)-1);
        strncat(buf, quoted, sizeof(buf)-1);
        free(quoted);
    }

    send_shellcommand(transport, serial, buf);
    return 0;
}

int uninstall_app(transport_type transport, char* serial, int argc, char** argv)
{
    /* if the user choose the -k option, we refuse to do it until devices are
       out with the option to uninstall the remaining data somehow (adb/ui) */
    if (argc == 3 && strcmp(argv[1], "-k") == 0)
    {
        printf(
            "The -k option uninstalls the application while retaining the data/cache.\n"
            "At the moment, there is no way to remove the remaining data.\n"
            "You will have to reinstall the application with the same signature, and fully uninstall it.\n"
            "If you truly wish to continue, execute 'adb shell pm uninstall -k %s'\n", argv[2]);
        return -1;
    }

    /* 'adb uninstall' takes the same arguments as 'pm uninstall' on device */
    return pm_command(transport, serial, argc, argv);
}

static int delete_file(transport_type transport, char* serial, char* filename)
{
    char buf[4096];
    char* quoted;

    snprintf(buf, sizeof(buf), "shell:rm ");
    quoted = dupAndQuote(filename);
    strncat(buf, quoted, sizeof(buf)-1);
    free(quoted);

    send_shellcommand(transport, serial, buf);
    return 0;
}

static const char* get_basename(const char* filename)
{
    const char* basename = adb_dirstop(filename);
    if (basename) {
        basename++;
        return basename;
    } else {
        return filename;
    }
}

static int check_file(const char* filename)
{
    struct stat st;

    if (filename == NULL) {
        return 0;
    }

    if (stat(filename, &st) != 0) {
        fprintf(stderr, "can't find '%s' to install\n", filename);
        return 1;
    }

    if (!S_ISREG(st.st_mode)) {
        fprintf(stderr, "can't install '%s' because it's not a file\n", filename);
        return 1;
    }

    return 0;
}

int install_app(transport_type transport, char* serial, int argc, char** argv)
{
    static const char *const DATA_DEST = "/data/local/tmp/%s";
    static const char *const SD_DEST = "/sdcard/tmp/%s";
    const char* where = DATA_DEST;
    char apk_dest[PATH_MAX];
    char verification_dest[PATH_MAX];
    char* apk_file;
    char* verification_file = NULL;
    int file_arg = -1;
    int err;
    int i;
    int verify_apk = 1;

    for (i = 1; i < argc; i++) {
        if (*argv[i] != '-') {
            file_arg = i;
            break;
        } else if (!strcmp(argv[i], "-i")) {
            // Skip the installer package name.
            i++;
        } else if (!strcmp(argv[i], "-s")) {
            where = SD_DEST;
        } else if (!strcmp(argv[i], "--algo")) {
            verify_apk = 0;
            i++;
        } else if (!strcmp(argv[i], "--iv")) {
            verify_apk = 0;
            i++;
        } else if (!strcmp(argv[i], "--key")) {
            verify_apk = 0;
            i++;
        }
    }

    if (file_arg < 0) {
        fprintf(stderr, "can't find filename in arguments\n");
        return 1;
    } else if (file_arg + 2 < argc) {
        fprintf(stderr, "too many files specified; only takes APK file and verifier file\n");
        return 1;
    }

    apk_file = argv[file_arg];

    if (file_arg != argc - 1) {
        verification_file = argv[file_arg + 1];
    }

    if (check_file(apk_file) || check_file(verification_file)) {
        return 1;
    }

    snprintf(apk_dest, sizeof apk_dest, where, get_basename(apk_file));
    if (verification_file != NULL) {
        snprintf(verification_dest, sizeof(verification_dest), where, get_basename(verification_file));

        if (!strcmp(apk_dest, verification_dest)) {
            fprintf(stderr, "APK and verification file can't have the same name\n");
            return 1;
        }
    }

    err = do_sync_push(apk_file, apk_dest, verify_apk);
    if (err) {
        goto cleanup_apk;
    } else {
        argv[file_arg] = apk_dest; /* destination name, not source location */
    }

    if (verification_file != NULL) {
        err = do_sync_push(verification_file, verification_dest, 0 /* no verify APK */);
        if (err) {
            goto cleanup_apk;
        } else {
            argv[file_arg + 1] = verification_dest; /* destination name, not source location */
        }
    }

    pm_command(transport, serial, argc, argv);

cleanup_apk:
    if (verification_file != NULL) {
        delete_file(transport, serial, verification_dest);
    }

    delete_file(transport, serial, apk_dest);

    return err;
}

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

#define TRACE_TAG TRACE_ADB

#include "sysdeps.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <string>

#include <base/stringprintf.h>

#if !defined(_WIN32)
#include <termios.h>
#include <unistd.h>
#endif

#include "adb.h"
#include "adb_auth.h"
#include "adb_client.h"
#include "adb_io.h"
#include "adb_utils.h"
#include "file_sync_service.h"

static int install_app(TransportType t, const char* serial, int argc, const char** argv);
static int install_multiple_app(TransportType t, const char* serial, int argc, const char** argv);
static int uninstall_app(TransportType t, const char* serial, int argc, const char** argv);

static std::string gProductOutPath;
extern int gListenAll;

static std::string product_file(const char *extra) {
    if (gProductOutPath.empty()) {
        fprintf(stderr, "adb: Product directory not specified; "
                "use -p or define ANDROID_PRODUCT_OUT\n");
        exit(1);
    }

    return android::base::StringPrintf("%s%s%s",
                                       gProductOutPath.c_str(), OS_PATH_SEPARATOR_STR, extra);
}

static void version(FILE* out) {
    fprintf(out, "Android Debug Bridge version %d.%d.%d\nRevision %s\n",
            ADB_VERSION_MAJOR, ADB_VERSION_MINOR, ADB_SERVER_VERSION, ADB_REVISION);
}

static void help() {
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
        "  adb push [-p] <local> <remote>\n"
        "                               - copy file/dir to device\n"
        "                                 ('-p' to display the transfer progress)\n"
        "  adb pull [-p] [-a] <remote> [<local>]\n"
        "                               - copy file/dir from device\n"
        "                                 ('-p' to display the transfer progress)\n"
        "                                 ('-a' means copy timestamp and mode)\n"
        "  adb sync [ <directory> ]     - copy host->device only if changed\n"
        "                                 (-l means list but don't copy)\n"
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
        "  adb reverse --list           - list all reverse socket connections from device\n"
        "  adb reverse <remote> <local> - reverse socket connections\n"
        "                                 reverse specs are one of:\n"
        "                                   tcp:<port>\n"
        "                                   localabstract:<unix domain socket name>\n"
        "                                   localreserved:<unix domain socket name>\n"
        "                                   localfilesystem:<unix domain socket name>\n"
        "  adb reverse --norebind <remote> <local>\n"
        "                               - same as 'adb reverse <remote> <local>' but fails\n"
        "                                 if <remote> is already reversed.\n"
        "  adb reverse --remove <remote>\n"
        "                               - remove a specific reversed socket connection\n"
        "  adb reverse --remove-all     - remove all reversed socket connections from device\n"
        "  adb jdwp                     - list PIDs of processes hosting a JDWP transport\n"
        "  adb install [-lrtsd] <file>\n"
        "  adb install-multiple [-lrtsdp] <file...>\n"
        "                               - push this package file to the device and install it\n"
        "                                 (-l: forward lock application)\n"
        "                                 (-r: replace existing application)\n"
        "                                 (-t: allow test packages)\n"
        "                                 (-s: install application on sdcard)\n"
        "                                 (-d: allow version code downgrade)\n"
        "                                 (-p: partial application install)\n"
        "  adb uninstall [-k] <package> - remove this app package from the device\n"
        "                                 ('-k' means keep the data and cache directories)\n"
        "  adb bugreport                - return all information from the device\n"
        "                                 that should be included in a bug report.\n"
        "\n"
        "  adb backup [-f <file>] [-apk|-noapk] [-obb|-noobb] [-shared|-noshared] [-all] [-system|-nosystem] [<packages...>]\n"
        "                               - write an archive of the device's data to <file>.\n"
        "                                 If no -f option is supplied then the data is written\n"
        "                                 to \"backup.ab\" in the current directory.\n"
        "                                 (-apk|-noapk enable/disable backup of the .apks themselves\n"
        "                                    in the archive; the default is noapk.)\n"
        "                                 (-obb|-noobb enable/disable backup of any installed apk expansion\n"
        "                                    (aka .obb) files associated with each application; the default\n"
        "                                    is noobb.)\n"
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
        "  adb disable-verity           - disable dm-verity checking on USERDEBUG builds\n"
        "  adb enable-verity            - re-enable dm-verity checking on USERDEBUG builds\n"
        "  adb keygen <file>            - generate adb public/private key. The private key is stored in <file>,\n"
        "                                 and the public key is stored in <file>.pub. Any existing files\n"
        "                                 are overwritten.\n"
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
        "  adb remount                  - remounts the /system, /vendor (if present) and /oem (if present) partitions on the device read-write\n"
        "  adb reboot [bootloader|recovery]\n"
        "                               - reboots the device, optionally into the bootloader or recovery program.\n"
        "  adb reboot sideload          - reboots the device into the sideload mode in recovery program (adb root required).\n"
        "  adb reboot sideload-auto-reboot\n"
        "                               - reboots into the sideload mode, then reboots automatically after the sideload regardless of the result.\n"
        "  adb sideload <file>          - sideloads the given package\n"
        "  adb root                     - restarts the adbd daemon with root permissions\n"
        "  adb unroot                   - restarts the adbd daemon without root permissions\n"
        "  adb usb                      - restarts the adbd daemon listening on USB\n"
        "  adb tcpip <port>             - restarts the adbd daemon listening on TCP on the specified port\n"
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
        "  - If <directory> is not specified, /system, /vendor (if present), /oem (if present) and /data partitions will be updated.\n"
        "\n"
        "  - If it is \"system\", \"vendor\", \"oem\" or \"data\", only the corresponding partition\n"
        "    is updated.\n"
        "\n"
        "environment variables:\n"
        "  ADB_TRACE                    - Print debug information. A comma separated list of the following values\n"
        "                                 1 or all, adb, sockets, packets, rwx, usb, sync, sysdeps, transport, jdwp\n"
        "  ANDROID_SERIAL               - The serial number to connect to. -s takes priority over this if given.\n"
        "  ANDROID_LOG_TAGS             - When used with the logcat option, only these debug tags are printed.\n"
        );
}

static int usage() {
    help();
    return 1;
}

#if defined(_WIN32)

// Implemented in sysdeps_win32.cpp.
void stdin_raw_init(int fd);
void stdin_raw_restore(int fd);

#else
static termios g_saved_terminal_state;

static void stdin_raw_init(int fd) {
    if (tcgetattr(fd, &g_saved_terminal_state)) return;

    termios tio;
    if (tcgetattr(fd, &tio)) return;

    cfmakeraw(&tio);

    // No timeout but request at least one character per read.
    tio.c_cc[VTIME] = 0;
    tio.c_cc[VMIN] = 1;

    tcsetattr(fd, TCSAFLUSH, &tio);
}

static void stdin_raw_restore(int fd) {
    tcsetattr(fd, TCSAFLUSH, &g_saved_terminal_state);
}
#endif

static void read_and_dump(int fd) {
    while (fd >= 0) {
        D("read_and_dump(): pre adb_read(fd=%d)\n", fd);
        char buf[BUFSIZ];
        int len = adb_read(fd, buf, sizeof(buf));
        D("read_and_dump(): post adb_read(fd=%d): len=%d\n", fd, len);
        if (len <= 0) {
            break;
        }

        fwrite(buf, 1, len, stdout);
        fflush(stdout);
    }
}

static void read_status_line(int fd, char* buf, size_t count)
{
    count--;
    while (count > 0) {
        int len = adb_read(fd, buf, count);
        if (len == 0) {
            break;
        } else if (len < 0) {
            if (errno == EINTR) continue;
            break;
        }

        buf += len;
        count -= len;
    }
    *buf = '\0';
}

static void copy_to_file(int inFd, int outFd) {
    const size_t BUFSIZE = 32 * 1024;
    char* buf = (char*) malloc(BUFSIZE);
    if (buf == nullptr) fatal("couldn't allocate buffer for copy_to_file");
    int len;
    long total = 0;

    D("copy_to_file(%d -> %d)\n", inFd, outFd);

    if (inFd == STDIN_FILENO) {
        stdin_raw_init(STDIN_FILENO);
    }

    while (true) {
        if (inFd == STDIN_FILENO) {
            len = unix_read(inFd, buf, BUFSIZE);
        } else {
            len = adb_read(inFd, buf, BUFSIZE);
        }
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
        if (outFd == STDOUT_FILENO) {
            fwrite(buf, 1, len, stdout);
            fflush(stdout);
        } else {
            adb_write(outFd, buf, len);
        }
        total += len;
    }

    if (inFd == STDIN_FILENO) {
        stdin_raw_restore(STDIN_FILENO);
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
                    stdin_raw_restore(fdi);
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

static int interactive_shell() {
    int fdi;

    std::string error;
    int fd = adb_connect("shell:", &error);
    if (fd < 0) {
        fprintf(stderr,"error: %s\n", error.c_str());
        return 1;
    }
    fdi = 0; //dup(0);

    int* fds = reinterpret_cast<int*>(malloc(sizeof(int) * 2));
    if (fds == nullptr) {
        fprintf(stderr, "couldn't allocate fds array: %s\n", strerror(errno));
        return 1;
    }

    fds[0] = fd;
    fds[1] = fdi;

    stdin_raw_init(fdi);

    adb_thread_create(stdin_read_thread, fds);
    read_and_dump(fd);
    stdin_raw_restore(fdi);
    return 0;
}


static std::string format_host_command(const char* command, TransportType type, const char* serial) {
    if (serial) {
        return android::base::StringPrintf("host-serial:%s:%s", serial, command);
    }

    const char* prefix = "host";
    if (type == kTransportUsb) {
        prefix = "host-usb";
    } else if (type == kTransportLocal) {
        prefix = "host-local";
    }
    return android::base::StringPrintf("%s:%s", prefix, command);
}

static int adb_download_buffer(const char *service, const char *fn, const void* data, unsigned sz,
                               bool show_progress)
{
    std::string error;
    int fd = adb_connect(android::base::StringPrintf("%s:%d", service, sz), &error);
    if (fd < 0) {
        fprintf(stderr,"error: %s\n", error.c_str());
        return -1;
    }

    int opt = CHUNK_SIZE;
    opt = adb_setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (const void *) &opt, sizeof(opt));

    unsigned total = sz;
    const uint8_t* ptr = reinterpret_cast<const uint8_t*>(data);

    if (show_progress) {
        char *x = strrchr(service, ':');
        if(x) service = x + 1;
    }

    while (sz > 0) {
        unsigned xfer = (sz > CHUNK_SIZE) ? CHUNK_SIZE : sz;
        if (!WriteFdExactly(fd, ptr, xfer)) {
            std::string error;
            adb_status(fd, &error);
            fprintf(stderr,"* failed to write data '%s' *\n", error.c_str());
            return -1;
        }
        sz -= xfer;
        ptr += xfer;
        if (show_progress) {
            printf("sending: '%s' %4d%%    \r", fn, (int)(100LL - ((100LL * sz) / (total))));
            fflush(stdout);
        }
    }
    if (show_progress) {
        printf("\n");
    }

    if (!adb_status(fd, &error)) {
        fprintf(stderr,"* error response '%s' *\n", error.c_str());
        return -1;
    }

    adb_close(fd);
    return 0;
}

#define SIDELOAD_HOST_BLOCK_SIZE (CHUNK_SIZE)

/*
 * The sideload-host protocol serves the data in a file (given on the
 * command line) to the client, using a simple protocol:
 *
 * - The connect message includes the total number of bytes in the
 *   file and a block size chosen by us.
 *
 * - The other side sends the desired block number as eight decimal
 *   digits (eg "00000023" for block 23).  Blocks are numbered from
 *   zero.
 *
 * - We send back the data of the requested block.  The last block is
 *   likely to be partial; when the last block is requested we only
 *   send the part of the block that exists, it's not padded up to the
 *   block size.
 *
 * - When the other side sends "DONEDONE" instead of a block number,
 *   we hang up.
 */
static int adb_sideload_host(const char* fn) {
    unsigned sz;
    size_t xfer = 0;
    int status;
    int last_percent = -1;
    int opt = SIDELOAD_HOST_BLOCK_SIZE;

    printf("loading: '%s'", fn);
    fflush(stdout);
    uint8_t* data = reinterpret_cast<uint8_t*>(load_file(fn, &sz));
    if (data == 0) {
        printf("\n");
        fprintf(stderr, "* cannot read '%s' *\n", fn);
        return -1;
    }

    std::string service =
            android::base::StringPrintf("sideload-host:%d:%d", sz, SIDELOAD_HOST_BLOCK_SIZE);
    std::string error;
    int fd = adb_connect(service, &error);
    if (fd < 0) {
        // Try falling back to the older sideload method.  Maybe this
        // is an older device that doesn't support sideload-host.
        printf("\n");
        status = adb_download_buffer("sideload", fn, data, sz, true);
        goto done;
    }

    opt = adb_setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (const void *) &opt, sizeof(opt));

    while (true) {
        char buf[9];
        if (!ReadFdExactly(fd, buf, 8)) {
            fprintf(stderr, "* failed to read command: %s\n", strerror(errno));
            status = -1;
            goto done;
        }
        buf[8] = '\0';

        if (strcmp("DONEDONE", buf) == 0) {
            status = 0;
            break;
        }

        int block = strtol(buf, NULL, 10);

        size_t offset = block * SIDELOAD_HOST_BLOCK_SIZE;
        if (offset >= sz) {
            fprintf(stderr, "* attempt to read block %d past end\n", block);
            status = -1;
            goto done;
        }
        uint8_t* start = data + offset;
        size_t offset_end = offset + SIDELOAD_HOST_BLOCK_SIZE;
        size_t to_write = SIDELOAD_HOST_BLOCK_SIZE;
        if (offset_end > sz) {
            to_write = sz - offset;
        }

        if(!WriteFdExactly(fd, start, to_write)) {
            adb_status(fd, &error);
            fprintf(stderr,"* failed to write data '%s' *\n", error.c_str());
            status = -1;
            goto done;
        }
        xfer += to_write;

        // For normal OTA packages, we expect to transfer every byte
        // twice, plus a bit of overhead (one read during
        // verification, one read of each byte for installation, plus
        // extra access to things like the zip central directory).
        // This estimate of the completion becomes 100% when we've
        // transferred ~2.13 (=100/47) times the package size.
        int percent = (int)(xfer * 47LL / (sz ? sz : 1));
        if (percent != last_percent) {
            printf("\rserving: '%s'  (~%d%%)    ", fn, percent);
            fflush(stdout);
            last_percent = percent;
        }
    }

    printf("\rTotal xfer: %.2fx%*s\n", (double)xfer / (sz ? sz : 1), (int)strlen(fn)+10, "");

  done:
    if (fd >= 0) adb_close(fd);
    free(data);
    return status;
}

/**
 * Run ppp in "notty" mode against a resource listed as the first parameter
 * eg:
 *
 * ppp dev:/dev/omap_csmi_tty0 <ppp options>
 *
 */
static int ppp(int argc, const char** argv) {
#if defined(_WIN32)
    fprintf(stderr, "error: adb %s not implemented on Win32\n", argv[0]);
    return -1;
#else
    if (argc < 2) {
        fprintf(stderr, "usage: adb %s <adb service name> [ppp opts]\n",
                argv[0]);

        return 1;
    }

    const char* adb_service_name = argv[1];
    std::string error;
    int fd = adb_connect(adb_service_name, &error);
    if (fd < 0) {
        fprintf(stderr,"Error: Could not open adb service: %s. Error: %s\n",
                adb_service_name, error.c_str());
        return 1;
    }

    pid_t pid = fork();

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
#endif /* !defined(_WIN32) */
}

static bool wait_for_device(const char* service, TransportType t, const char* serial) {
    // Was the caller vague about what they'd like us to wait for?
    // If so, check they weren't more specific in their choice of transport type.
    if (strcmp(service, "wait-for-device") == 0) {
        if (t == kTransportUsb) {
            service = "wait-for-usb";
        } else if (t == kTransportLocal) {
            service = "wait-for-local";
        } else {
            service = "wait-for-any";
        }
    }

    std::string cmd = format_host_command(service, t, serial);
    return adb_command(cmd);
}

static int send_shell_command(TransportType transport_type, const char* serial,
                              const std::string& command) {
    int fd;
    while (true) {
        std::string error;
        fd = adb_connect(command, &error);
        if (fd >= 0) {
            break;
        }
        fprintf(stderr,"- waiting for device -\n");
        adb_sleep_ms(1000);
        wait_for_device("wait-for-device", transport_type, serial);
    }

    read_and_dump(fd);
    int rc = adb_close(fd);
    if (rc) {
        perror("close");
    }
    return rc;
}

static int logcat(TransportType transport, const char* serial, int argc, const char** argv) {
    char* log_tags = getenv("ANDROID_LOG_TAGS");
    std::string quoted = escape_arg(log_tags == nullptr ? "" : log_tags);

    std::string cmd = "shell:export ANDROID_LOG_TAGS=\"" + quoted + "\"; exec logcat";

    if (!strcmp(argv[0], "longcat")) {
        cmd += " -v long";
    }

    --argc;
    ++argv;
    while (argc-- > 0) {
        cmd += " " + escape_arg(*argv++);
    }

    return send_shell_command(transport, serial, cmd);
}

static int mkdirs(const char *path)
{
    int ret;
    char *x = (char *)path + 1;

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

static int backup(int argc, const char** argv) {
    const char* filename = "./backup.ab";

    /* find, extract, and use any -f argument */
    for (int i = 1; i < argc; i++) {
        if (!strcmp("-f", argv[i])) {
            if (i == argc-1) {
                fprintf(stderr, "adb: -f passed with no filename\n");
                return usage();
            }
            filename = argv[i+1];
            for (int j = i+2; j <= argc; ) {
                argv[i++] = argv[j++];
            }
            argc -= 2;
            argv[argc] = NULL;
        }
    }

    /* bare "adb backup" or "adb backup -f filename" are not valid invocations */
    if (argc < 2) return usage();

    adb_unlink(filename);
    mkdirs(filename);
    int outFd = adb_creat(filename, 0640);
    if (outFd < 0) {
        fprintf(stderr, "adb: unable to open file %s\n", filename);
        return -1;
    }

    std::string cmd = "backup:";
    --argc;
    ++argv;
    while (argc-- > 0) {
        cmd += " " + escape_arg(*argv++);
    }

    D("backup. filename=%s cmd=%s\n", filename, cmd.c_str());
    std::string error;
    int fd = adb_connect(cmd, &error);
    if (fd < 0) {
        fprintf(stderr, "adb: unable to connect for backup: %s\n", error.c_str());
        adb_close(outFd);
        return -1;
    }

    printf("Now unlock your device and confirm the backup operation.\n");
    copy_to_file(fd, outFd);

    adb_close(fd);
    adb_close(outFd);
    return 0;
}

static int restore(int argc, const char** argv) {
    if (argc != 2) return usage();

    const char* filename = argv[1];
    int tarFd = adb_open(filename, O_RDONLY);
    if (tarFd < 0) {
        fprintf(stderr, "adb: unable to open file %s: %s\n", filename, strerror(errno));
        return -1;
    }

    std::string error;
    int fd = adb_connect("restore:", &error);
    if (fd < 0) {
        fprintf(stderr, "adb: unable to connect for restore: %s\n", error.c_str());
        adb_close(tarFd);
        return -1;
    }

    printf("Now unlock your device and confirm the restore operation.\n");
    copy_to_file(tarFd, fd);

    adb_close(fd);
    adb_close(tarFd);
    return 0;
}

/* <hint> may be:
 * - A simple product name
 *   e.g., "sooner"
 * - A relative path from the CWD to the ANDROID_PRODUCT_OUT dir
 *   e.g., "out/target/product/sooner"
 * - An absolute path to the PRODUCT_OUT dir
 *   e.g., "/src/device/out/target/product/sooner"
 *
 * Given <hint>, try to construct an absolute path to the
 * ANDROID_PRODUCT_OUT dir.
 */
static std::string find_product_out_path(const char* hint) {
    if (hint == NULL || hint[0] == '\0') {
        return "";
    }

    // If it's already absolute, don't bother doing any work.
    if (adb_is_absolute_host_path(hint)) {
        return hint;
    }

    // If there are any slashes in it, assume it's a relative path;
    // make it absolute.
    if (adb_dirstart(hint) != nullptr) {
        std::string cwd;
        if (!getcwd(&cwd)) {
            fprintf(stderr, "adb: getcwd failed: %s\n", strerror(errno));
            return "";
        }
        return android::base::StringPrintf("%s%s%s", cwd.c_str(), OS_PATH_SEPARATOR_STR, hint);
    }

    // It's a string without any slashes.  Try to do something with it.
    //
    // Try to find the root of the build tree, and build a PRODUCT_OUT
    // path from there.
    char* top = getenv("ANDROID_BUILD_TOP");
    if (top == nullptr) {
        fprintf(stderr, "adb: ANDROID_BUILD_TOP not set!\n");
        return "";
    }

    std::string path = top;
    path += OS_PATH_SEPARATOR_STR;
    path += "out";
    path += OS_PATH_SEPARATOR_STR;
    path += "target";
    path += OS_PATH_SEPARATOR_STR;
    path += "product";
    path += OS_PATH_SEPARATOR_STR;
    path += hint;
    if (!directory_exists(path)) {
        fprintf(stderr, "adb: Couldn't find a product dir based on -p %s; "
                        "\"%s\" doesn't exist\n", hint, path.c_str());
        return "";
    }
    return path;
}

static void parse_push_pull_args(const char **arg, int narg, char const **path1,
                                 char const **path2, int *show_progress,
                                 int *copy_attrs) {
    *show_progress = 0;
    *copy_attrs = 0;

    while (narg > 0) {
        if (!strcmp(*arg, "-p")) {
            *show_progress = 1;
        } else if (!strcmp(*arg, "-a")) {
            *copy_attrs = 1;
        } else {
            break;
        }
        ++arg;
        --narg;
    }

    if (narg > 0) {
        *path1 = *arg;
        ++arg;
        --narg;
    }

    if (narg > 0) {
        *path2 = *arg;
    }
}

static int adb_connect_command(const std::string& command) {
    std::string error;
    int fd = adb_connect(command, &error);
    if (fd < 0) {
        fprintf(stderr, "error: %s\n", error.c_str());
        return 1;
    }
    read_and_dump(fd);
    adb_close(fd);
    return 0;
}

static int adb_query_command(const std::string& command) {
    std::string result;
    std::string error;
    if (!adb_query(command, &result, &error)) {
        fprintf(stderr, "error: %s\n", error.c_str());
        return 1;
    }
    printf("%s\n", result.c_str());
    return 0;
}

int adb_commandline(int argc, const char **argv) {
    int no_daemon = 0;
    int is_daemon = 0;
    int is_server = 0;
    int r;
    TransportType transport_type = kTransportAny;

    // If defined, this should be an absolute path to
    // the directory containing all of the various system images
    // for a particular product.  If not defined, and the adb
    // command requires this information, then the user must
    // specify the path using "-p".
    char* ANDROID_PRODUCT_OUT = getenv("ANDROID_PRODUCT_OUT");
    if (ANDROID_PRODUCT_OUT != nullptr) {
        gProductOutPath = ANDROID_PRODUCT_OUT;
    }
    // TODO: also try TARGET_PRODUCT/TARGET_DEVICE as a hint

    const char* serial = getenv("ANDROID_SERIAL");

    /* Validate and assign the server port */
    const char* server_port_str = getenv("ANDROID_ADB_SERVER_PORT");
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
    while (argc > 0) {
        if (!strcmp(argv[0],"server")) {
            is_server = 1;
        } else if (!strcmp(argv[0],"nodaemon")) {
            no_daemon = 1;
        } else if (!strcmp(argv[0], "fork-server")) {
            /* this is a special flag used only when the ADB client launches the ADB Server */
            is_daemon = 1;
        } else if (!strncmp(argv[0], "-p", 2)) {
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
            if (gProductOutPath.empty()) {
                fprintf(stderr, "adb: could not resolve \"-p %s\"\n", product);
                return usage();
            }
        } else if (argv[0][0]=='-' && argv[0][1]=='s') {
            if (isdigit(argv[0][2])) {
                serial = argv[0] + 2;
            } else {
                if (argc < 2 || argv[0][2] != '\0') return usage();
                serial = argv[1];
                argc--;
                argv++;
            }
        } else if (!strcmp(argv[0],"-d")) {
            transport_type = kTransportUsb;
        } else if (!strcmp(argv[0],"-e")) {
            transport_type = kTransportLocal;
        } else if (!strcmp(argv[0],"-a")) {
            gListenAll = 1;
        } else if (!strncmp(argv[0], "-H", 2)) {
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

        } else if (!strncmp(argv[0], "-P", 2)) {
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

    adb_set_transport(transport_type, serial);
    adb_set_tcp_specifics(server_port);

    if (is_server) {
        if (no_daemon || is_daemon) {
            r = adb_main(is_daemon, server_port);
        } else {
            r = launch_server(server_port);
        }
        if (r) {
            fprintf(stderr,"* could not start server *\n");
        }
        return r;
    }

    if (argc == 0) {
        return usage();
    }

    /* handle wait-for-* prefix */
    if (!strncmp(argv[0], "wait-for-", strlen("wait-for-"))) {
        const char* service = argv[0];

        if (!wait_for_device(service, transport_type, serial)) {
            return 1;
        }

        // Allow a command to be run after wait-for-device,
        // e.g. 'adb wait-for-device shell'.
        if (argc == 1) {
            return 0;
        }

        /* Fall through */
        argc--;
        argv++;
    }

    /* adb_connect() commands */
    if (!strcmp(argv[0], "devices")) {
        const char *listopt;
        if (argc < 2) {
            listopt = "";
        } else if (argc == 2 && !strcmp(argv[1], "-l")) {
            listopt = argv[1];
        } else {
            fprintf(stderr, "Usage: adb devices [-l]\n");
            return 1;
        }

        std::string query = android::base::StringPrintf("host:%s%s", argv[0], listopt);
        printf("List of devices attached\n");
        return adb_query_command(query);
    }
    else if (!strcmp(argv[0], "connect")) {
        if (argc != 2) {
            fprintf(stderr, "Usage: adb connect <host>[:<port>]\n");
            return 1;
        }

        std::string query = android::base::StringPrintf("host:connect:%s", argv[1]);
        return adb_query_command(query);
    }
    else if (!strcmp(argv[0], "disconnect")) {
        if (argc > 2) {
            fprintf(stderr, "Usage: adb disconnect [<host>[:<port>]]\n");
            return 1;
        }

        std::string query = android::base::StringPrintf("host:disconnect:%s",
                                                        (argc == 2) ? argv[1] : "");
        return adb_query_command(query);
    }
    else if (!strcmp(argv[0], "emu")) {
        return adb_send_emulator_command(argc, argv, serial);
    }
    else if (!strcmp(argv[0], "shell") || !strcmp(argv[0], "hell")) {
        char h = (argv[0][0] == 'h');

        if (h) {
            printf("\x1b[41;33m");
            fflush(stdout);
        }

        if (argc < 2) {
            D("starting interactive shell\n");
            r = interactive_shell();
            if (h) {
                printf("\x1b[0m");
                fflush(stdout);
            }
            return r;
        }

        std::string cmd = "shell:";
        --argc;
        ++argv;
        while (argc-- > 0) {
            // We don't escape here, just like ssh(1). http://b/20564385.
            cmd += *argv++;
            if (*argv) cmd += " ";
        }

        while (true) {
            D("interactive shell loop. cmd=%s\n", cmd.c_str());
            std::string error;
            int fd = adb_connect(cmd, &error);
            int r;
            if (fd >= 0) {
                D("about to read_and_dump(fd=%d)\n", fd);
                read_and_dump(fd);
                D("read_and_dump() done.\n");
                adb_close(fd);
                r = 0;
            } else {
                fprintf(stderr,"error: %s\n", error.c_str());
                r = -1;
            }

            if (h) {
                printf("\x1b[0m");
                fflush(stdout);
            }
            D("interactive shell loop. return r=%d\n", r);
            return r;
        }
    }
    else if (!strcmp(argv[0], "exec-in") || !strcmp(argv[0], "exec-out")) {
        int exec_in = !strcmp(argv[0], "exec-in");

        std::string cmd = "exec:";
        cmd += argv[1];
        argc -= 2;
        argv += 2;
        while (argc-- > 0) {
            cmd += " " + escape_arg(*argv++);
        }

        std::string error;
        int fd = adb_connect(cmd, &error);
        if (fd < 0) {
            fprintf(stderr, "error: %s\n", error.c_str());
            return -1;
        }

        if (exec_in) {
            copy_to_file(STDIN_FILENO, fd);
        } else {
            copy_to_file(fd, STDOUT_FILENO);
        }

        adb_close(fd);
        return 0;
    }
    else if (!strcmp(argv[0], "kill-server")) {
        std::string error;
        int fd = _adb_connect("host:kill", &error);
        if (fd == -1) {
            fprintf(stderr,"* server not running *\n");
            return 1;
        }
        return 0;
    }
    else if (!strcmp(argv[0], "sideload")) {
        if (argc != 2) return usage();
        if (adb_sideload_host(argv[1])) {
            return 1;
        } else {
            return 0;
        }
    }
    else if (!strcmp(argv[0], "remount") ||
             !strcmp(argv[0], "reboot") ||
             !strcmp(argv[0], "reboot-bootloader") ||
             !strcmp(argv[0], "tcpip") ||
             !strcmp(argv[0], "usb") ||
             !strcmp(argv[0], "root") ||
             !strcmp(argv[0], "unroot") ||
             !strcmp(argv[0], "disable-verity") ||
             !strcmp(argv[0], "enable-verity")) {
        std::string command;
        if (!strcmp(argv[0], "reboot-bootloader")) {
            command = "reboot:bootloader";
        } else if (argc > 1) {
            command = android::base::StringPrintf("%s:%s", argv[0], argv[1]);
        } else {
            command = android::base::StringPrintf("%s:", argv[0]);
        }
        return adb_connect_command(command);
    }
    else if (!strcmp(argv[0], "bugreport")) {
        if (argc != 1) return usage();
        return send_shell_command(transport_type, serial, "shell:bugreport");
    }
    else if (!strcmp(argv[0], "forward") || !strcmp(argv[0], "reverse")) {
        bool reverse = !strcmp(argv[0], "reverse");
        ++argv;
        --argc;
        if (argc < 1) return usage();

        // Determine the <host-prefix> for this command.
        std::string host_prefix;
        if (reverse) {
            host_prefix = "reverse";
        } else {
            if (serial) {
                host_prefix = android::base::StringPrintf("host-serial:%s", serial);
            } else if (transport_type == kTransportUsb) {
                host_prefix = "host-usb";
            } else if (transport_type == kTransportLocal) {
                host_prefix = "host-local";
            } else {
                host_prefix = "host";
            }
        }

        std::string cmd;
        if (strcmp(argv[0], "--list") == 0) {
            if (argc != 1) return usage();
            return adb_query_command(host_prefix + ":list-forward");
        } else if (strcmp(argv[0], "--remove-all") == 0) {
            if (argc != 1) return usage();
            cmd = host_prefix + ":killforward-all";
        } else if (strcmp(argv[0], "--remove") == 0) {
            // forward --remove <local>
            if (argc != 2) return usage();
            cmd = host_prefix + ":killforward:" + argv[1];
        } else if (strcmp(argv[0], "--no-rebind") == 0) {
            // forward --no-rebind <local> <remote>
            if (argc != 3) return usage();
            cmd = host_prefix + ":forward:norebind:" + argv[1] + ";" + argv[2];
        } else {
            // forward <local> <remote>
            if (argc != 2) return usage();
            cmd = host_prefix + ":forward:" + argv[0] + ";" + argv[1];
        }

        return adb_command(cmd) ? 0 : 1;
    }
    /* do_sync_*() commands */
    else if (!strcmp(argv[0], "ls")) {
        if (argc != 2) return usage();
        return do_sync_ls(argv[1]);
    }
    else if (!strcmp(argv[0], "push")) {
        int show_progress = 0;
        int copy_attrs = 0; // unused
        const char* lpath = NULL, *rpath = NULL;

        parse_push_pull_args(&argv[1], argc - 1, &lpath, &rpath, &show_progress, &copy_attrs);

        if ((lpath != NULL) && (rpath != NULL)) {
            return do_sync_push(lpath, rpath, show_progress);
        }

        return usage();
    }
    else if (!strcmp(argv[0], "pull")) {
        int show_progress = 0;
        int copy_attrs = 0;
        const char* rpath = NULL, *lpath = ".";

        parse_push_pull_args(&argv[1], argc - 1, &rpath, &lpath, &show_progress, &copy_attrs);

        if (rpath != NULL) {
            return do_sync_pull(rpath, lpath, show_progress, copy_attrs);
        }

        return usage();
    }
    else if (!strcmp(argv[0], "install")) {
        if (argc < 2) return usage();
        return install_app(transport_type, serial, argc, argv);
    }
    else if (!strcmp(argv[0], "install-multiple")) {
        if (argc < 2) return usage();
        return install_multiple_app(transport_type, serial, argc, argv);
    }
    else if (!strcmp(argv[0], "uninstall")) {
        if (argc < 2) return usage();
        return uninstall_app(transport_type, serial, argc, argv);
    }
    else if (!strcmp(argv[0], "sync")) {
        std::string src;
        bool list_only = false;
        if (argc < 2) {
            // No local path was specified.
            src = "";
        } else if (argc >= 2 && strcmp(argv[1], "-l") == 0) {
            list_only = true;
            if (argc == 3) {
                src = argv[2];
            } else {
                src = "";
            }
        } else if (argc == 2) {
            // A local path or "android"/"data" arg was specified.
            src = argv[1];
        } else {
            return usage();
        }

        if (src != "" &&
            src != "system" && src != "data" && src != "vendor" && src != "oem") {
            return usage();
        }

        std::string system_src_path = product_file("system");
        std::string data_src_path = product_file("data");
        std::string vendor_src_path = product_file("vendor");
        std::string oem_src_path = product_file("oem");

        int rc = 0;
        if (rc == 0 && (src.empty() || src == "system")) {
            rc = do_sync_sync(system_src_path, "/system", list_only);
        }
        if (rc == 0 && (src.empty() || src == "vendor") && directory_exists(vendor_src_path)) {
            rc = do_sync_sync(vendor_src_path, "/vendor", list_only);
        }
        if (rc == 0 && (src.empty() || src == "oem") && directory_exists(oem_src_path)) {
            rc = do_sync_sync(oem_src_path, "/oem", list_only);
        }
        if (rc == 0 && (src.empty() || src == "data")) {
            rc = do_sync_sync(data_src_path, "/data", list_only);
        }
        return rc;
    }
    /* passthrough commands */
    else if (!strcmp(argv[0],"get-state") ||
        !strcmp(argv[0],"get-serialno") ||
        !strcmp(argv[0],"get-devpath"))
    {
        return adb_query_command(format_host_command(argv[0], transport_type, serial));
    }
    /* other commands */
    else if (!strcmp(argv[0],"logcat") || !strcmp(argv[0],"lolcat") || !strcmp(argv[0],"longcat")) {
        return logcat(transport_type, serial, argc, argv);
    }
    else if (!strcmp(argv[0],"ppp")) {
        return ppp(argc, argv);
    }
    else if (!strcmp(argv[0], "start-server")) {
        std::string error;
        return adb_connect("host:start-server", &error);
    }
    else if (!strcmp(argv[0], "backup")) {
        return backup(argc, argv);
    }
    else if (!strcmp(argv[0], "restore")) {
        return restore(argc, argv);
    }
    else if (!strcmp(argv[0], "keygen")) {
        if (argc < 2) return usage();
        return adb_auth_keygen(argv[1]);
    }
    else if (!strcmp(argv[0], "jdwp")) {
        return adb_connect_command("jdwp");
    }
    /* "adb /?" is a common idiom under Windows */
    else if (!strcmp(argv[0], "help") || !strcmp(argv[0], "/?")) {
        help();
        return 0;
    }
    else if (!strcmp(argv[0], "version")) {
        version(stdout);
        return 0;
    }

    usage();
    return 1;
}

static int pm_command(TransportType transport, const char* serial, int argc, const char** argv) {
    std::string cmd = "shell:pm";

    while (argc-- > 0) {
        cmd += " " + escape_arg(*argv++);
    }

    return send_shell_command(transport, serial, cmd);
}

static int uninstall_app(TransportType transport, const char* serial, int argc, const char** argv) {
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

static int delete_file(TransportType transport, const char* serial, char* filename) {
    std::string cmd = "shell:rm -f " + escape_arg(filename);
    return send_shell_command(transport, serial, cmd);
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

static int install_app(TransportType transport, const char* serial, int argc, const char** argv) {
    static const char *const DATA_DEST = "/data/local/tmp/%s";
    static const char *const SD_DEST = "/sdcard/tmp/%s";
    const char* where = DATA_DEST;
    int i;
    struct stat sb;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-s")) {
            where = SD_DEST;
        }
    }

    // Find last APK argument.
    // All other arguments passed through verbatim.
    int last_apk = -1;
    for (i = argc - 1; i >= 0; i--) {
        const char* file = argv[i];
        char* dot = strrchr(file, '.');
        if (dot && !strcasecmp(dot, ".apk")) {
            if (stat(file, &sb) == -1 || !S_ISREG(sb.st_mode)) {
                fprintf(stderr, "Invalid APK file: %s\n", file);
                return -1;
            }

            last_apk = i;
            break;
        }
    }

    if (last_apk == -1) {
        fprintf(stderr, "Missing APK file\n");
        return -1;
    }

    const char* apk_file = argv[last_apk];
    char apk_dest[PATH_MAX];
    snprintf(apk_dest, sizeof apk_dest, where, get_basename(apk_file));
    int err = do_sync_push(apk_file, apk_dest, 0 /* no show progress */);
    if (err) {
        goto cleanup_apk;
    } else {
        argv[last_apk] = apk_dest; /* destination name, not source location */
    }

    err = pm_command(transport, serial, argc, argv);

cleanup_apk:
    delete_file(transport, serial, apk_dest);
    return err;
}

static int install_multiple_app(TransportType transport, const char* serial, int argc,
                                const char** argv)
{
    int i;
    struct stat sb;
    uint64_t total_size = 0;

    // Find all APK arguments starting at end.
    // All other arguments passed through verbatim.
    int first_apk = -1;
    for (i = argc - 1; i >= 0; i--) {
        const char* file = argv[i];
        char* dot = strrchr(file, '.');
        if (dot && !strcasecmp(dot, ".apk")) {
            if (stat(file, &sb) == -1 || !S_ISREG(sb.st_mode)) {
                fprintf(stderr, "Invalid APK file: %s\n", file);
                return -1;
            }

            total_size += sb.st_size;
            first_apk = i;
        } else {
            break;
        }
    }

    if (first_apk == -1) {
        fprintf(stderr, "Missing APK file\n");
        return 1;
    }

    std::string cmd = android::base::StringPrintf("exec:pm install-create -S %" PRIu64, total_size);
    for (i = 1; i < first_apk; i++) {
        cmd += " " + escape_arg(argv[i]);
    }

    // Create install session
    std::string error;
    int fd = adb_connect(cmd, &error);
    if (fd < 0) {
        fprintf(stderr, "Connect error for create: %s\n", error.c_str());
        return -1;
    }
    char buf[BUFSIZ];
    read_status_line(fd, buf, sizeof(buf));
    adb_close(fd);

    int session_id = -1;
    if (!strncmp("Success", buf, 7)) {
        char* start = strrchr(buf, '[');
        char* end = strrchr(buf, ']');
        if (start && end) {
            *end = '\0';
            session_id = strtol(start + 1, NULL, 10);
        }
    }
    if (session_id < 0) {
        fprintf(stderr, "Failed to create session\n");
        fputs(buf, stderr);
        return -1;
    }

    // Valid session, now stream the APKs
    int success = 1;
    for (i = first_apk; i < argc; i++) {
        const char* file = argv[i];
        if (stat(file, &sb) == -1) {
            fprintf(stderr, "Failed to stat %s\n", file);
            success = 0;
            goto finalize_session;
        }

        std::string cmd = android::base::StringPrintf(
                "exec:pm install-write -S %" PRIu64 " %d %d_%s -",
                static_cast<uint64_t>(sb.st_size), session_id, i, get_basename(file));

        int localFd = adb_open(file, O_RDONLY);
        if (localFd < 0) {
            fprintf(stderr, "Failed to open %s: %s\n", file, strerror(errno));
            success = 0;
            goto finalize_session;
        }

        std::string error;
        int remoteFd = adb_connect(cmd, &error);
        if (remoteFd < 0) {
            fprintf(stderr, "Connect error for write: %s\n", error.c_str());
            adb_close(localFd);
            success = 0;
            goto finalize_session;
        }

        copy_to_file(localFd, remoteFd);
        read_status_line(remoteFd, buf, sizeof(buf));

        adb_close(localFd);
        adb_close(remoteFd);

        if (strncmp("Success", buf, 7)) {
            fprintf(stderr, "Failed to write %s\n", file);
            fputs(buf, stderr);
            success = 0;
            goto finalize_session;
        }
    }

finalize_session:
    // Commit session if we streamed everything okay; otherwise abandon
    std::string service =
            android::base::StringPrintf("exec:pm install-%s %d",
                                        success ? "commit" : "abandon", session_id);
    fd = adb_connect(service, &error);
    if (fd < 0) {
        fprintf(stderr, "Connect error for finalize: %s\n", error.c_str());
        return -1;
    }
    read_status_line(fd, buf, sizeof(buf));
    adb_close(fd);

    if (!strncmp("Success", buf, 7)) {
        fputs(buf, stderr);
        return 0;
    } else {
        fprintf(stderr, "Failed to finalize session\n");
        fputs(buf, stderr);
        return -1;
    }
}

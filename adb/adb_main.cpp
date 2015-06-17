/*
 * Copyright (C) 2015 The Android Open Source Project
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

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

#include "adb.h"
#include "adb_auth.h"
#include "adb_listeners.h"
#include "transport.h"

#include <base/stringprintf.h>

#if !ADB_HOST
#include <getopt.h>
#include <sys/prctl.h>

#include "cutils/properties.h"
#include "private/android_filesystem_config.h"
#include "selinux/selinux.h"

#include "qemu_tracing.h"
#endif

static void adb_cleanup(void)
{
    usb_cleanup();
}

#if defined(_WIN32)
static BOOL WINAPI ctrlc_handler(DWORD type)
{
    exit(STATUS_CONTROL_C_EXIT);
    return TRUE;
}
#endif

#if ADB_HOST
#ifdef WORKAROUND_BUG6558362
#include <sched.h>
#define AFFINITY_ENVVAR "ADB_CPU_AFFINITY_BUG6558362"
void adb_set_affinity(void)
{
   cpu_set_t cpu_set;
   const char* cpunum_str = getenv(AFFINITY_ENVVAR);
   char* strtol_res;
   int cpu_num;

   if (!cpunum_str || !*cpunum_str)
       return;
   cpu_num = strtol(cpunum_str, &strtol_res, 0);
   if (*strtol_res != '\0')
     fatal("bad number (%s) in env var %s. Expecting 0..n.\n", cpunum_str, AFFINITY_ENVVAR);

   sched_getaffinity(0, sizeof(cpu_set), &cpu_set);
   D("orig cpu_set[0]=0x%08lx\n", cpu_set.__bits[0]);
   CPU_ZERO(&cpu_set);
   CPU_SET(cpu_num, &cpu_set);
   sched_setaffinity(0, sizeof(cpu_set), &cpu_set);
   sched_getaffinity(0, sizeof(cpu_set), &cpu_set);
   D("new cpu_set[0]=0x%08lx\n", cpu_set.__bits[0]);
}
#endif
#else /* ADB_HOST */
static const char *root_seclabel = NULL;

static void drop_capabilities_bounding_set_if_needed() {
#ifdef ALLOW_ADBD_ROOT
    char value[PROPERTY_VALUE_MAX];
    property_get("ro.debuggable", value, "");
    if (strcmp(value, "1") == 0) {
        return;
    }
#endif
    int i;
    for (i = 0; prctl(PR_CAPBSET_READ, i, 0, 0, 0) >= 0; i++) {
        if (i == CAP_SETUID || i == CAP_SETGID) {
            // CAP_SETUID CAP_SETGID needed by /system/bin/run-as
            continue;
        }
        int err = prctl(PR_CAPBSET_DROP, i, 0, 0, 0);

        // Some kernels don't have file capabilities compiled in, and
        // prctl(PR_CAPBSET_DROP) returns EINVAL. Don't automatically
        // die when we see such misconfigured kernels.
        if ((err < 0) && (errno != EINVAL)) {
            exit(1);
        }
    }
}

static bool should_drop_privileges() {
#if defined(ALLOW_ADBD_ROOT)
    char value[PROPERTY_VALUE_MAX];

    // The emulator is never secure, so don't drop privileges there.
    // TODO: this seems like a bug --- shouldn't the emulator behave like a device?
    property_get("ro.kernel.qemu", value, "");
    if (strcmp(value, "1") == 0) {
        return false;
    }

    // The properties that affect `adb root` and `adb unroot` are ro.secure and
    // ro.debuggable. In this context the names don't make the expected behavior
    // particularly obvious.
    //
    // ro.debuggable:
    //   Allowed to become root, but not necessarily the default. Set to 1 on
    //   eng and userdebug builds.
    //
    // ro.secure:
    //   Drop privileges by default. Set to 1 on userdebug and user builds.
    property_get("ro.secure", value, "1");
    bool ro_secure = (strcmp(value, "1") == 0);

    property_get("ro.debuggable", value, "");
    bool ro_debuggable = (strcmp(value, "1") == 0);

    // Drop privileges if ro.secure is set...
    bool drop = ro_secure;

    property_get("service.adb.root", value, "");
    bool adb_root = (strcmp(value, "1") == 0);
    bool adb_unroot = (strcmp(value, "0") == 0);

    // ...except "adb root" lets you keep privileges in a debuggable build.
    if (ro_debuggable && adb_root) {
        drop = false;
    }

    // ...and "adb unroot" lets you explicitly drop privileges.
    if (adb_unroot) {
        drop = true;
    }

    return drop;
#else
    return true; // "adb root" not allowed, always drop privileges.
#endif /* ALLOW_ADBD_ROOT */
}
#endif /* ADB_HOST */

void start_logging(void)
{
#if defined(_WIN32)
    char    temp[ MAX_PATH ];
    FILE*   fnul;
    FILE*   flog;

    GetTempPath( sizeof(temp) - 8, temp );
    strcat( temp, "adb.log" );

    /* Win32 specific redirections */
    fnul = fopen( "NUL", "rt" );
    if (fnul != NULL)
        stdin[0] = fnul[0];

    flog = fopen( temp, "at" );
    if (flog == NULL)
        flog = fnul;

    setvbuf( flog, NULL, _IONBF, 0 );

    stdout[0] = flog[0];
    stderr[0] = flog[0];
    fprintf(stderr,"--- adb starting (pid %d) ---\n", getpid());
#else
    int fd;

    fd = unix_open("/dev/null", O_RDONLY);
    dup2(fd, 0);
    adb_close(fd);

    fd = unix_open("/tmp/adb.log", O_WRONLY | O_CREAT | O_APPEND, 0640);
    if(fd < 0) {
        fd = unix_open("/dev/null", O_WRONLY);
    }
    dup2(fd, 1);
    dup2(fd, 2);
    adb_close(fd);
    fprintf(stderr,"--- adb starting (pid %d) ---\n", getpid());
#endif
}

int adb_main(int is_daemon, int server_port)
{
#if !ADB_HOST
    int port;
    char value[PROPERTY_VALUE_MAX];

    umask(000);
#endif

    atexit(adb_cleanup);
#if defined(_WIN32)
    SetConsoleCtrlHandler( ctrlc_handler, TRUE );
#else
    // No SIGCHLD. Let the service subproc handle its children.
    signal(SIGPIPE, SIG_IGN);
#endif

    init_transport_registration();

#if ADB_HOST
    HOST = 1;

#ifdef WORKAROUND_BUG6558362
    if(is_daemon) adb_set_affinity();
#endif
    usb_init();
    local_init(DEFAULT_ADB_LOCAL_TRANSPORT_PORT);
    adb_auth_init();

    std::string local_name = android::base::StringPrintf("tcp:%d", server_port);
    if (install_listener(local_name, "*smartsocket*", NULL, 0)) {
        exit(1);
    }
#else
    // We need to call this even if auth isn't enabled because the file
    // descriptor will always be open.
    adbd_cloexec_auth_socket();

    if (ALLOW_ADBD_NO_AUTH && property_get_bool("ro.adb.secure", 0) == 0) {
        auth_required = false;
    }

    adbd_auth_init();

    // Our external storage path may be different than apps, since
    // we aren't able to bind mount after dropping root.
    const char* adb_external_storage = getenv("ADB_EXTERNAL_STORAGE");
    if (NULL != adb_external_storage) {
        setenv("EXTERNAL_STORAGE", adb_external_storage, 1);
    } else {
        D("Warning: ADB_EXTERNAL_STORAGE is not set.  Leaving EXTERNAL_STORAGE"
          " unchanged.\n");
    }

    /* add extra groups:
    ** AID_ADB to access the USB driver
    ** AID_LOG to read system logs (adb logcat)
    ** AID_INPUT to diagnose input issues (getevent)
    ** AID_INET to diagnose network issues (ping)
    ** AID_NET_BT and AID_NET_BT_ADMIN to diagnose bluetooth (hcidump)
    ** AID_SDCARD_R to allow reading from the SD card
    ** AID_SDCARD_RW to allow writing to the SD card
    ** AID_NET_BW_STATS to read out qtaguid statistics
    */
    gid_t groups[] = { AID_ADB, AID_LOG, AID_INPUT, AID_INET, AID_NET_BT,
                       AID_NET_BT_ADMIN, AID_SDCARD_R, AID_SDCARD_RW,
                       AID_NET_BW_STATS };
    if (setgroups(sizeof(groups)/sizeof(groups[0]), groups) != 0) {
        exit(1);
    }

    /* don't listen on a port (default 5037) if running in secure mode */
    /* don't run as root if we are running in secure mode */
    if (should_drop_privileges()) {
        drop_capabilities_bounding_set_if_needed();

        /* then switch user and group to "shell" */
        if (setgid(AID_SHELL) != 0) {
            exit(1);
        }
        if (setuid(AID_SHELL) != 0) {
            exit(1);
        }

        D("Local port disabled\n");
    } else {
        if ((root_seclabel != NULL) && (is_selinux_enabled() > 0)) {
            // b/12587913: fix setcon to allow const pointers
            if (setcon((char *)root_seclabel) < 0) {
                exit(1);
            }
        }
        std::string local_name = android::base::StringPrintf("tcp:%d", server_port);
        if (install_listener(local_name, "*smartsocket*", NULL, 0)) {
            exit(1);
        }
    }

    int usb = 0;
    if (access(USB_ADB_PATH, F_OK) == 0 || access(USB_FFS_ADB_EP0, F_OK) == 0) {
        // listen on USB
        usb_init();
        usb = 1;
    }

    // If one of these properties is set, also listen on that port
    // If one of the properties isn't set and we couldn't listen on usb,
    // listen on the default port.
    property_get("service.adb.tcp.port", value, "");
    if (!value[0]) {
        property_get("persist.adb.tcp.port", value, "");
    }
    if (sscanf(value, "%d", &port) == 1 && port > 0) {
        printf("using port=%d\n", port);
        // listen on TCP port specified by service.adb.tcp.port property
        local_init(port);
    } else if (!usb) {
        // listen on default port
        local_init(DEFAULT_ADB_LOCAL_TRANSPORT_PORT);
    }

    D("adb_main(): pre init_jdwp()\n");
    init_jdwp();
    D("adb_main(): post init_jdwp()\n");
#endif

    if (is_daemon)
    {
        // inform our parent that we are up and running.
#if defined(_WIN32)
        DWORD  count;
        WriteFile( GetStdHandle( STD_OUTPUT_HANDLE ), "OK\n", 3, &count, NULL );
#else
        fprintf(stderr, "OK\n");
#endif
        start_logging();
    }
    D("Event loop starting\n");

    fdevent_loop();

    usb_cleanup();

    return 0;
}

#if !ADB_HOST
void close_stdin() {
    int fd = unix_open("/dev/null", O_RDONLY);
    if (fd == -1) {
        perror("failed to open /dev/null, stdin will remain open");
        return;
    }
    dup2(fd, 0);
    adb_close(fd);
}
#endif

// TODO(danalbert): Split this file up into adb_main.cpp and adbd_main.cpp.
int main(int argc, char **argv) {
#if ADB_HOST
    // adb client/server
    adb_sysdeps_init();
    adb_trace_init();
    D("Handling commandline()\n");
    return adb_commandline(argc - 1, const_cast<const char**>(argv + 1));
#else
    // adbd
    while (true) {
        static struct option opts[] = {
            {"root_seclabel", required_argument, nullptr, 's'},
            {"device_banner", required_argument, nullptr, 'b'},
            {"version", no_argument, nullptr, 'v'},
        };

        int option_index = 0;
        int c = getopt_long(argc, argv, "", opts, &option_index);
        if (c == -1)
            break;
        switch (c) {
        case 's':
            root_seclabel = optarg;
            break;
        case 'b':
            adb_device_banner = optarg;
            break;
        case 'v':
            printf("Android Debug Bridge Daemon version %d.%d.%d %s\n",
                   ADB_VERSION_MAJOR, ADB_VERSION_MINOR, ADB_SERVER_VERSION,
                   ADB_REVISION);
            return 0;
        default:
            break;
        }
    }

    close_stdin();

    adb_trace_init();

    /* If adbd runs inside the emulator this will enable adb tracing via
     * adb-debug qemud service in the emulator. */
    adb_qemu_trace_init();

    D("Handling main()\n");
    return adb_main(0, DEFAULT_ADB_PORT);
#endif
}

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
#include "adb.h"

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#include <string>

#include <base/stringprintf.h>
#include <base/strings.h>

#include "adb_auth.h"
#include "adb_io.h"
#include "adb_listeners.h"
#include "transport.h"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

#if !ADB_HOST
#include <cutils/properties.h>
#include <sys/capability.h>
#include <sys/mount.h>
#endif

ADB_MUTEX_DEFINE( D_lock );

int HOST = 0;

#if !ADB_HOST
const char *adb_device_banner = "device";
#endif

void fatal(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "error: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    exit(-1);
}

void fatal_errno(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "error: %s: ", strerror(errno));
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    exit(-1);
}

#if !ADB_HOST
void start_device_log(void) {
    struct tm now;
    time_t t;
    tzset();
    time(&t);
    localtime_r(&t, &now);

    char timestamp[PATH_MAX];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d-%H-%M-%S", &now);

    std::string path = android::base::StringPrintf("/data/adb/adb-%s-%d", timestamp, getpid());
    int fd = unix_open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0640);
    if (fd == -1) {
        return;
    }

    // redirect stdout and stderr to the log file
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    fprintf(stderr, "--- adb starting (pid %d) ---\n", getpid());
    adb_close(fd);
}
#endif

int adb_trace_mask;

std::string get_trace_setting_from_env() {
    const char* setting = getenv("ADB_TRACE");
    if (setting == nullptr) {
        setting = "";
    }

    return std::string(setting);
}

#if !ADB_HOST
std::string get_trace_setting_from_prop() {
    char buf[PROPERTY_VALUE_MAX];
    property_get("persist.adb.trace_mask", buf, "");
    return std::string(buf);
}
#endif

std::string get_trace_setting() {
#if ADB_HOST
    return get_trace_setting_from_env();
#else
    return get_trace_setting_from_prop();
#endif
}

// Split the comma/space/colum/semi-column separated list of tags from the trace
// setting and build the trace mask from it. note that '1' and 'all' are special
// cases to enable all tracing.
//
// adb's trace setting comes from the ADB_TRACE environment variable, whereas
// adbd's comes from the system property persist.adb.trace_mask.
void adb_trace_init() {
    const std::string trace_setting = get_trace_setting();

    static const struct {
        const char*  tag;
        int           flag;
    } tags[] = {
        { "1", 0 },
        { "all", 0 },
        { "adb", TRACE_ADB },
        { "sockets", TRACE_SOCKETS },
        { "packets", TRACE_PACKETS },
        { "rwx", TRACE_RWX },
        { "usb", TRACE_USB },
        { "sync", TRACE_SYNC },
        { "sysdeps", TRACE_SYSDEPS },
        { "transport", TRACE_TRANSPORT },
        { "jdwp", TRACE_JDWP },
        { "services", TRACE_SERVICES },
        { "auth", TRACE_AUTH },
        { NULL, 0 }
    };

    if (trace_setting.empty()) {
        return;
    }

    // Use a comma/colon/semi-colon/space separated list
    const char* p = trace_setting.c_str();
    while (*p) {
        int  len, tagn;

        const char* q = strpbrk(p, " ,:;");
        if (q == NULL) {
            q = p + strlen(p);
        }
        len = q - p;

        for (tagn = 0; tags[tagn].tag != NULL; tagn++) {
            int  taglen = strlen(tags[tagn].tag);

            if (len == taglen && !memcmp(tags[tagn].tag, p, len)) {
                int  flag = tags[tagn].flag;
                if (flag == 0) {
                    adb_trace_mask = ~0;
                    return;
                }
                adb_trace_mask |= (1 << flag);
                break;
            }
        }
        p = q;
        if (*p)
            p++;
    }

#if !ADB_HOST
    start_device_log();
#endif
}

apacket* get_apacket(void)
{
    apacket* p = reinterpret_cast<apacket*>(malloc(sizeof(apacket)));
    if (p == nullptr) {
      fatal("failed to allocate an apacket");
    }

    memset(p, 0, sizeof(apacket) - MAX_PAYLOAD);
    return p;
}

void put_apacket(apacket *p)
{
    free(p);
}

void handle_online(atransport *t)
{
    D("adb: online\n");
    t->online = 1;
}

void handle_offline(atransport *t)
{
    D("adb: offline\n");
    //Close the associated usb
    t->online = 0;
    run_transport_disconnects(t);
}

#if DEBUG_PACKETS
#define DUMPMAX 32
void print_packet(const char *label, apacket *p)
{
    char *tag;
    char *x;
    unsigned count;

    switch(p->msg.command){
    case A_SYNC: tag = "SYNC"; break;
    case A_CNXN: tag = "CNXN" ; break;
    case A_OPEN: tag = "OPEN"; break;
    case A_OKAY: tag = "OKAY"; break;
    case A_CLSE: tag = "CLSE"; break;
    case A_WRTE: tag = "WRTE"; break;
    case A_AUTH: tag = "AUTH"; break;
    default: tag = "????"; break;
    }

    fprintf(stderr, "%s: %s %08x %08x %04x \"",
            label, tag, p->msg.arg0, p->msg.arg1, p->msg.data_length);
    count = p->msg.data_length;
    x = (char*) p->data;
    if(count > DUMPMAX) {
        count = DUMPMAX;
        tag = "\n";
    } else {
        tag = "\"\n";
    }
    while(count-- > 0){
        if((*x >= ' ') && (*x < 127)) {
            fputc(*x, stderr);
        } else {
            fputc('.', stderr);
        }
        x++;
    }
    fputs(tag, stderr);
}
#endif

static void send_ready(unsigned local, unsigned remote, atransport *t)
{
    D("Calling send_ready \n");
    apacket *p = get_apacket();
    p->msg.command = A_OKAY;
    p->msg.arg0 = local;
    p->msg.arg1 = remote;
    send_packet(p, t);
}

static void send_close(unsigned local, unsigned remote, atransport *t)
{
    D("Calling send_close \n");
    apacket *p = get_apacket();
    p->msg.command = A_CLSE;
    p->msg.arg0 = local;
    p->msg.arg1 = remote;
    send_packet(p, t);
}

static size_t fill_connect_data(char *buf, size_t bufsize)
{
#if ADB_HOST
    return snprintf(buf, bufsize, "host::") + 1;
#else
    static const char *cnxn_props[] = {
        "ro.product.name",
        "ro.product.model",
        "ro.product.device",
    };
    static const int num_cnxn_props = ARRAY_SIZE(cnxn_props);
    int i;
    size_t remaining = bufsize;
    size_t len;

    len = snprintf(buf, remaining, "%s::", adb_device_banner);
    remaining -= len;
    buf += len;
    for (i = 0; i < num_cnxn_props; i++) {
        char value[PROPERTY_VALUE_MAX];
        property_get(cnxn_props[i], value, "");
        len = snprintf(buf, remaining, "%s=%s;", cnxn_props[i], value);
        remaining -= len;
        buf += len;
    }

    return bufsize - remaining + 1;
#endif
}

void send_connect(atransport *t)
{
    D("Calling send_connect \n");
    apacket *cp = get_apacket();
    cp->msg.command = A_CNXN;
    cp->msg.arg0 = A_VERSION;
    cp->msg.arg1 = MAX_PAYLOAD;
    cp->msg.data_length = fill_connect_data((char *)cp->data,
                                            sizeof(cp->data));
    send_packet(cp, t);
}

// qual_overwrite is used to overwrite a qualifier string.  dst is a
// pointer to a char pointer.  It is assumed that if *dst is non-NULL, it
// was malloc'ed and needs to freed.  *dst will be set to a dup of src.
// TODO: switch to std::string for these atransport fields instead.
static void qual_overwrite(char** dst, const std::string& src) {
    free(*dst);
    *dst = strdup(src.c_str());
}

void parse_banner(const char* banner, atransport* t) {
    D("parse_banner: %s\n", banner);

    // The format is something like:
    // "device::ro.product.name=x;ro.product.model=y;ro.product.device=z;".
    std::vector<std::string> pieces = android::base::Split(banner, ":");

    if (pieces.size() > 2) {
        const std::string& props = pieces[2];
        for (auto& prop : android::base::Split(props, ";")) {
            // The list of properties was traditionally ;-terminated rather than ;-separated.
            if (prop.empty()) continue;

            std::vector<std::string> key_value = android::base::Split(prop, "=");
            if (key_value.size() != 2) continue;

            const std::string& key = key_value[0];
            const std::string& value = key_value[1];
            if (key == "ro.product.name") {
                qual_overwrite(&t->product, value);
            } else if (key == "ro.product.model") {
                qual_overwrite(&t->model, value);
            } else if (key == "ro.product.device") {
                qual_overwrite(&t->device, value);
            }
        }
    }

    const std::string& type = pieces[0];
    if (type == "bootloader") {
        D("setting connection_state to CS_BOOTLOADER\n");
        t->connection_state = CS_BOOTLOADER;
        update_transports();
    } else if (type == "device") {
        D("setting connection_state to CS_DEVICE\n");
        t->connection_state = CS_DEVICE;
        update_transports();
    } else if (type == "recovery") {
        D("setting connection_state to CS_RECOVERY\n");
        t->connection_state = CS_RECOVERY;
        update_transports();
    } else if (type == "sideload") {
        D("setting connection_state to CS_SIDELOAD\n");
        t->connection_state = CS_SIDELOAD;
        update_transports();
    } else {
        D("setting connection_state to CS_HOST\n");
        t->connection_state = CS_HOST;
    }
}

void handle_packet(apacket *p, atransport *t)
{
    asocket *s;

    D("handle_packet() %c%c%c%c\n", ((char*) (&(p->msg.command)))[0],
            ((char*) (&(p->msg.command)))[1],
            ((char*) (&(p->msg.command)))[2],
            ((char*) (&(p->msg.command)))[3]);
    print_packet("recv", p);

    switch(p->msg.command){
    case A_SYNC:
        if(p->msg.arg0){
            send_packet(p, t);
            if(HOST) send_connect(t);
        } else {
            t->connection_state = CS_OFFLINE;
            handle_offline(t);
            send_packet(p, t);
        }
        return;

    case A_CNXN: /* CONNECT(version, maxdata, "system-id-string") */
            /* XXX verify version, etc */
        if(t->connection_state != CS_OFFLINE) {
            t->connection_state = CS_OFFLINE;
            handle_offline(t);
        }

        parse_banner(reinterpret_cast<const char*>(p->data), t);

        if (HOST || !auth_required) {
            handle_online(t);
            if (!HOST) send_connect(t);
        } else {
            send_auth_request(t);
        }
        break;

    case A_AUTH:
        if (p->msg.arg0 == ADB_AUTH_TOKEN) {
            t->connection_state = CS_UNAUTHORIZED;
            t->key = adb_auth_nextkey(t->key);
            if (t->key) {
                send_auth_response(p->data, p->msg.data_length, t);
            } else {
                /* No more private keys to try, send the public key */
                send_auth_publickey(t);
            }
        } else if (p->msg.arg0 == ADB_AUTH_SIGNATURE) {
            if (adb_auth_verify(t->token, p->data, p->msg.data_length)) {
                adb_auth_verified(t);
                t->failed_auth_attempts = 0;
            } else {
                if (t->failed_auth_attempts++ > 10)
                    adb_sleep_ms(1000);
                send_auth_request(t);
            }
        } else if (p->msg.arg0 == ADB_AUTH_RSAPUBLICKEY) {
            adb_auth_confirm_key(p->data, p->msg.data_length, t);
        }
        break;

    case A_OPEN: /* OPEN(local-id, 0, "destination") */
        if (t->online && p->msg.arg0 != 0 && p->msg.arg1 == 0) {
            char *name = (char*) p->data;
            name[p->msg.data_length > 0 ? p->msg.data_length - 1 : 0] = 0;
            s = create_local_service_socket(name);
            if(s == 0) {
                send_close(0, p->msg.arg0, t);
            } else {
                s->peer = create_remote_socket(p->msg.arg0, t);
                s->peer->peer = s;
                send_ready(s->id, s->peer->id, t);
                s->ready(s);
            }
        }
        break;

    case A_OKAY: /* READY(local-id, remote-id, "") */
        if (t->online && p->msg.arg0 != 0 && p->msg.arg1 != 0) {
            if((s = find_local_socket(p->msg.arg1, 0))) {
                if(s->peer == 0) {
                    /* On first READY message, create the connection. */
                    s->peer = create_remote_socket(p->msg.arg0, t);
                    s->peer->peer = s;
                    s->ready(s);
                } else if (s->peer->id == p->msg.arg0) {
                    /* Other READY messages must use the same local-id */
                    s->ready(s);
                } else {
                    D("Invalid A_OKAY(%d,%d), expected A_OKAY(%d,%d) on transport %s\n",
                      p->msg.arg0, p->msg.arg1, s->peer->id, p->msg.arg1, t->serial);
                }
            }
        }
        break;

    case A_CLSE: /* CLOSE(local-id, remote-id, "") or CLOSE(0, remote-id, "") */
        if (t->online && p->msg.arg1 != 0) {
            if((s = find_local_socket(p->msg.arg1, p->msg.arg0))) {
                /* According to protocol.txt, p->msg.arg0 might be 0 to indicate
                 * a failed OPEN only. However, due to a bug in previous ADB
                 * versions, CLOSE(0, remote-id, "") was also used for normal
                 * CLOSE() operations.
                 *
                 * This is bad because it means a compromised adbd could
                 * send packets to close connections between the host and
                 * other devices. To avoid this, only allow this if the local
                 * socket has a peer on the same transport.
                 */
                if (p->msg.arg0 == 0 && s->peer && s->peer->transport != t) {
                    D("Invalid A_CLSE(0, %u) from transport %s, expected transport %s\n",
                      p->msg.arg1, t->serial, s->peer->transport->serial);
                } else {
                    s->close(s);
                }
            }
        }
        break;

    case A_WRTE: /* WRITE(local-id, remote-id, <data>) */
        if (t->online && p->msg.arg0 != 0 && p->msg.arg1 != 0) {
            if((s = find_local_socket(p->msg.arg1, p->msg.arg0))) {
                unsigned rid = p->msg.arg0;
                p->len = p->msg.data_length;

                if(s->enqueue(s, p) == 0) {
                    D("Enqueue the socket\n");
                    send_ready(s->id, rid, t);
                }
                return;
            }
        }
        break;

    default:
        printf("handle_packet: what is %08x?!\n", p->msg.command);
    }

    put_apacket(p);
}

#if ADB_HOST

int launch_server(int server_port)
{
#if defined(_WIN32)
    /* we need to start the server in the background                    */
    /* we create a PIPE that will be used to wait for the server's "OK" */
    /* message since the pipe handles must be inheritable, we use a     */
    /* security attribute                                               */
    HANDLE                pipe_read, pipe_write;
    HANDLE                stdout_handle, stderr_handle;
    SECURITY_ATTRIBUTES   sa;
    STARTUPINFO           startup;
    PROCESS_INFORMATION   pinfo;
    char                  program_path[ MAX_PATH ];
    int                   ret;

    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;

    /* create pipe, and ensure its read handle isn't inheritable */
    ret = CreatePipe( &pipe_read, &pipe_write, &sa, 0 );
    if (!ret) {
        fprintf(stderr, "CreatePipe() failure, error %ld\n", GetLastError() );
        return -1;
    }

    SetHandleInformation( pipe_read, HANDLE_FLAG_INHERIT, 0 );

    /* Some programs want to launch an adb command and collect its output by
     * calling CreateProcess with inheritable stdout/stderr handles, then
     * using read() to get its output. When this happens, the stdout/stderr
     * handles passed to the adb client process will also be inheritable.
     * When starting the adb server here, care must be taken to reset them
     * to non-inheritable.
     * Otherwise, something bad happens: even if the adb command completes,
     * the calling process is stuck while read()-ing from the stdout/stderr
     * descriptors, because they're connected to corresponding handles in the
     * adb server process (even if the latter never uses/writes to them).
     */
    stdout_handle = GetStdHandle( STD_OUTPUT_HANDLE );
    stderr_handle = GetStdHandle( STD_ERROR_HANDLE );
    if (stdout_handle != INVALID_HANDLE_VALUE) {
        SetHandleInformation( stdout_handle, HANDLE_FLAG_INHERIT, 0 );
    }
    if (stderr_handle != INVALID_HANDLE_VALUE) {
        SetHandleInformation( stderr_handle, HANDLE_FLAG_INHERIT, 0 );
    }

    ZeroMemory( &startup, sizeof(startup) );
    startup.cb = sizeof(startup);
    startup.hStdInput  = GetStdHandle( STD_INPUT_HANDLE );
    startup.hStdOutput = pipe_write;
    startup.hStdError  = GetStdHandle( STD_ERROR_HANDLE );
    startup.dwFlags    = STARTF_USESTDHANDLES;

    ZeroMemory( &pinfo, sizeof(pinfo) );

    /* get path of current program */
    GetModuleFileName( NULL, program_path, sizeof(program_path) );
    char args[64];
    snprintf(args, sizeof(args), "adb -P %d fork-server server",  server_port);
    ret = CreateProcess(
            program_path,                              /* program path  */
            args,
                                    /* the fork-server argument will set the
                                       debug = 2 in the child           */
            NULL,                   /* process handle is not inheritable */
            NULL,                    /* thread handle is not inheritable */
            TRUE,                          /* yes, inherit some handles */
            DETACHED_PROCESS, /* the new process doesn't have a console */
            NULL,                     /* use parent's environment block */
            NULL,                    /* use parent's starting directory */
            &startup,                 /* startup info, i.e. std handles */
            &pinfo );

    CloseHandle( pipe_write );

    if (!ret) {
        fprintf(stderr, "CreateProcess failure, error %ld\n", GetLastError() );
        CloseHandle( pipe_read );
        return -1;
    }

    CloseHandle( pinfo.hProcess );
    CloseHandle( pinfo.hThread );

    /* wait for the "OK\n" message */
    {
        char  temp[3];
        DWORD  count;

        ret = ReadFile( pipe_read, temp, 3, &count, NULL );
        CloseHandle( pipe_read );
        if ( !ret ) {
            fprintf(stderr, "could not read ok from ADB Server, error = %ld\n", GetLastError() );
            return -1;
        }
        if (count != 3 || temp[0] != 'O' || temp[1] != 'K' || temp[2] != '\n') {
            fprintf(stderr, "ADB server didn't ACK\n" );
            return -1;
        }
    }
#else /* !defined(_WIN32) */
    char    path[PATH_MAX];
    int     fd[2];

    // set up a pipe so the child can tell us when it is ready.
    // fd[0] will be parent's end, and fd[1] will get mapped to stderr in the child.
    if (pipe(fd)) {
        fprintf(stderr, "pipe failed in launch_server, errno: %d\n", errno);
        return -1;
    }
    get_my_path(path, PATH_MAX);
    pid_t pid = fork();
    if(pid < 0) return -1;

    if (pid == 0) {
        // child side of the fork

        // redirect stderr to the pipe
        // we use stderr instead of stdout due to stdout's buffering behavior.
        adb_close(fd[0]);
        dup2(fd[1], STDERR_FILENO);
        adb_close(fd[1]);

        char str_port[30];
        snprintf(str_port, sizeof(str_port), "%d",  server_port);
        // child process
        int result = execl(path, "adb", "-P", str_port, "fork-server", "server", NULL);
        // this should not return
        fprintf(stderr, "OOPS! execl returned %d, errno: %d\n", result, errno);
    } else  {
        // parent side of the fork

        char  temp[3];

        temp[0] = 'A'; temp[1] = 'B'; temp[2] = 'C';
        // wait for the "OK\n" message
        adb_close(fd[1]);
        int ret = adb_read(fd[0], temp, 3);
        int saved_errno = errno;
        adb_close(fd[0]);
        if (ret < 0) {
            fprintf(stderr, "could not read ok from ADB Server, errno = %d\n", saved_errno);
            return -1;
        }
        if (ret != 3 || temp[0] != 'O' || temp[1] != 'K' || temp[2] != '\n') {
            fprintf(stderr, "ADB server didn't ACK\n" );
            return -1;
        }

        setsid();
    }
#endif /* !defined(_WIN32) */
    return 0;
}
#endif /* ADB_HOST */

// Try to handle a network forwarding request.
// This returns 1 on success, 0 on failure, and -1 to indicate this is not
// a forwarding-related request.
int handle_forward_request(const char* service, transport_type ttype, char* serial, int reply_fd)
{
    if (!strcmp(service, "list-forward")) {
        // Create the list of forward redirections.
        std::string listeners = format_listeners();
#if ADB_HOST
        SendOkay(reply_fd);
#endif
        SendProtocolString(reply_fd, listeners);
        return 1;
    }

    if (!strcmp(service, "killforward-all")) {
        remove_all_listeners();
#if ADB_HOST
        /* On the host: 1st OKAY is connect, 2nd OKAY is status */
        SendOkay(reply_fd);
#endif
        SendOkay(reply_fd);
        return 1;
    }

    if (!strncmp(service, "forward:",8) ||
        !strncmp(service, "killforward:",12)) {
        char *local, *remote;
        atransport *transport;

        int createForward = strncmp(service, "kill", 4);
        int no_rebind = 0;

        local = strchr(service, ':') + 1;

        // Handle forward:norebind:<local>... here
        if (createForward && !strncmp(local, "norebind:", 9)) {
            no_rebind = 1;
            local = strchr(local, ':') + 1;
        }

        remote = strchr(local,';');

        if (createForward) {
            // Check forward: parameter format: '<local>;<remote>'
            if(remote == 0) {
                SendFail(reply_fd, "malformed forward spec");
                return 1;
            }

            *remote++ = 0;
            if((local[0] == 0) || (remote[0] == 0) || (remote[0] == '*')) {
                SendFail(reply_fd, "malformed forward spec");
                return 1;
            }
        } else {
            // Check killforward: parameter format: '<local>'
            if (local[0] == 0) {
                SendFail(reply_fd, "malformed forward spec");
                return 1;
            }
        }

        std::string error_msg;
        transport = acquire_one_transport(CS_ANY, ttype, serial, &error_msg);
        if (!transport) {
            SendFail(reply_fd, error_msg);
            return 1;
        }

        install_status_t r;
        if (createForward) {
            r = install_listener(local, remote, transport, no_rebind);
        } else {
            r = remove_listener(local, transport);
        }
        if (r == INSTALL_STATUS_OK) {
#if ADB_HOST
            /* On the host: 1st OKAY is connect, 2nd OKAY is status */
            SendOkay(reply_fd);
#endif
            SendOkay(reply_fd);
            return 1;
        }

        std::string message;
        switch (r) {
          case INSTALL_STATUS_OK: message = " "; break;
          case INSTALL_STATUS_INTERNAL_ERROR: message = "internal error"; break;
          case INSTALL_STATUS_CANNOT_BIND:
            message = android::base::StringPrintf("cannot bind to socket: %s", strerror(errno));
            break;
          case INSTALL_STATUS_CANNOT_REBIND:
            message = android::base::StringPrintf("cannot rebind existing socket: %s", strerror(errno));
            break;
          case INSTALL_STATUS_LISTENER_NOT_FOUND: message = "listener not found"; break;
        }
        SendFail(reply_fd, message);
        return 1;
    }
    return 0;
}

int handle_host_request(char *service, transport_type ttype, char* serial, int reply_fd, asocket *s)
{
    if(!strcmp(service, "kill")) {
        fprintf(stderr,"adb server killed by remote request\n");
        fflush(stdout);
        SendOkay(reply_fd);
        usb_cleanup();
        exit(0);
    }

#if ADB_HOST
    atransport *transport = NULL;
    // "transport:" is used for switching transport with a specified serial number
    // "transport-usb:" is used for switching transport to the only USB transport
    // "transport-local:" is used for switching transport to the only local transport
    // "transport-any:" is used for switching transport to the only transport
    if (!strncmp(service, "transport", strlen("transport"))) {
        transport_type type = kTransportAny;

        if (!strncmp(service, "transport-usb", strlen("transport-usb"))) {
            type = kTransportUsb;
        } else if (!strncmp(service, "transport-local", strlen("transport-local"))) {
            type = kTransportLocal;
        } else if (!strncmp(service, "transport-any", strlen("transport-any"))) {
            type = kTransportAny;
        } else if (!strncmp(service, "transport:", strlen("transport:"))) {
            service += strlen("transport:");
            serial = service;
        }

        std::string error_msg = "unknown failure";
        transport = acquire_one_transport(CS_ANY, type, serial, &error_msg);

        if (transport) {
            s->transport = transport;
            SendOkay(reply_fd);
        } else {
            SendFail(reply_fd, error_msg);
        }
        return 1;
    }

    // return a list of all connected devices
    if (!strncmp(service, "devices", 7)) {
        bool long_listing = (strcmp(service+7, "-l") == 0);
        if (long_listing || service[7] == 0) {
            D("Getting device list...\n");
            std::string device_list = list_transports(long_listing);
            D("Sending device list...\n");
            SendOkay(reply_fd);
            SendProtocolString(reply_fd, device_list);
            return 0;
        }
        return 1;
    }

    // remove TCP transport
    if (!strncmp(service, "disconnect:", 11)) {
        char buffer[4096];
        memset(buffer, 0, sizeof(buffer));
        char* serial = service + 11;
        if (serial[0] == 0) {
            // disconnect from all TCP devices
            unregister_all_tcp_transports();
        } else {
            char hostbuf[100];
            // assume port 5555 if no port is specified
            if (!strchr(serial, ':')) {
                snprintf(hostbuf, sizeof(hostbuf) - 1, "%s:5555", serial);
                serial = hostbuf;
            }
            atransport *t = find_transport(serial);

            if (t) {
                unregister_transport(t);
            } else {
                snprintf(buffer, sizeof(buffer), "No such device %s", serial);
            }
        }

        SendOkay(reply_fd);
        SendProtocolString(reply_fd, buffer);
        return 0;
    }

    // returns our value for ADB_SERVER_VERSION
    if (!strcmp(service, "version")) {
        SendOkay(reply_fd);
        SendProtocolString(reply_fd, android::base::StringPrintf("%04x", ADB_SERVER_VERSION));
        return 0;
    }

    if(!strncmp(service,"get-serialno",strlen("get-serialno"))) {
        const char *out = "unknown";
        transport = acquire_one_transport(CS_ANY, ttype, serial, NULL);
        if (transport && transport->serial) {
            out = transport->serial;
        }
        SendOkay(reply_fd);
        SendProtocolString(reply_fd, out);
        return 0;
    }
    if(!strncmp(service,"get-devpath",strlen("get-devpath"))) {
        const char *out = "unknown";
        transport = acquire_one_transport(CS_ANY, ttype, serial, NULL);
        if (transport && transport->devpath) {
            out = transport->devpath;
        }
        SendOkay(reply_fd);
        SendProtocolString(reply_fd, out);
        return 0;
    }
    // indicates a new emulator instance has started
    if (!strncmp(service,"emulator:",9)) {
        int  port = atoi(service+9);
        local_connect(port);
        /* we don't even need to send a reply */
        return 0;
    }

    if(!strncmp(service,"get-state",strlen("get-state"))) {
        transport = acquire_one_transport(CS_ANY, ttype, serial, NULL);
        SendOkay(reply_fd);
        SendProtocolString(reply_fd, transport ? transport->connection_state_name() : "unknown");
        return 0;
    }
#endif // ADB_HOST

    int ret = handle_forward_request(service, ttype, serial, reply_fd);
    if (ret >= 0)
      return ret - 1;
    return -1;
}

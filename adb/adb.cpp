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

#define TRACE_TAG ADB

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

#include <chrono>
#include <condition_variable>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <android-base/errors.h>
#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/macros.h>
#include <android-base/parsenetaddress.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>

#include "adb_auth.h"
#include "adb_io.h"
#include "adb_listeners.h"
#include "adb_unique_fd.h"
#include "adb_utils.h"
#include "sysdeps/chrono.h"
#include "transport.h"

#if !ADB_HOST
#include <sys/capability.h>
#include <sys/mount.h>
#include <android-base/properties.h>
using namespace std::chrono_literals;
#endif

std::string adb_version() {
    // Don't change the format of this --- it's parsed by ddmlib.
    return android::base::StringPrintf(
        "Android Debug Bridge version %d.%d.%d\n"
        "Version %s\n"
        "Installed as %s\n",
        ADB_VERSION_MAJOR, ADB_VERSION_MINOR, ADB_SERVER_VERSION, ADB_VERSION,
        android::base::GetExecutablePath().c_str());
}

void fatal(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    char buf[1024];
    vsnprintf(buf, sizeof(buf), fmt, ap);

#if ADB_HOST
    fprintf(stderr, "error: %s\n", buf);
#else
    LOG(ERROR) << "error: " << buf;
#endif

    va_end(ap);
    abort();
}

void fatal_errno(const char* fmt, ...) {
    int err = errno;
    va_list ap;
    va_start(ap, fmt);
    char buf[1024];
    vsnprintf(buf, sizeof(buf), fmt, ap);

#if ADB_HOST
    fprintf(stderr, "error: %s: %s\n", buf, strerror(err));
#else
    LOG(ERROR) << "error: " << buf << ": " << strerror(err);
#endif

    va_end(ap);
    abort();
}

uint32_t calculate_apacket_checksum(const apacket* p) {
    uint32_t sum = 0;
    for (size_t i = 0; i < p->msg.data_length; ++i) {
        sum += static_cast<uint8_t>(p->payload[i]);
    }
    return sum;
}

apacket* get_apacket(void)
{
    apacket* p = new apacket();
    if (p == nullptr) {
      fatal("failed to allocate an apacket");
    }

    memset(&p->msg, 0, sizeof(p->msg));
    return p;
}

void put_apacket(apacket *p)
{
    delete p;
}

void handle_online(atransport *t)
{
    D("adb: online");
    t->online = 1;
}

void handle_offline(atransport *t)
{
    D("adb: offline");
    //Close the associated usb
    t->online = 0;

    // This is necessary to avoid a race condition that occurred when a transport closes
    // while a client socket is still active.
    close_all_sockets(t);

    t->RunDisconnects();
}

#if DEBUG_PACKETS
#define DUMPMAX 32
void print_packet(const char *label, apacket *p)
{
    const char* tag;
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
    const char* x = p->payload.data();
    if (count > DUMPMAX) {
        count = DUMPMAX;
        tag = "\n";
    } else {
        tag = "\"\n";
    }
    while (count-- > 0) {
        if ((*x >= ' ') && (*x < 127)) {
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
    D("Calling send_ready");
    apacket *p = get_apacket();
    p->msg.command = A_OKAY;
    p->msg.arg0 = local;
    p->msg.arg1 = remote;
    send_packet(p, t);
}

static void send_close(unsigned local, unsigned remote, atransport *t)
{
    D("Calling send_close");
    apacket *p = get_apacket();
    p->msg.command = A_CLSE;
    p->msg.arg0 = local;
    p->msg.arg1 = remote;
    send_packet(p, t);
}

std::string get_connection_string() {
    std::vector<std::string> connection_properties;

#if !ADB_HOST
    static const char* cnxn_props[] = {
        "ro.product.name",
        "ro.product.model",
        "ro.product.device",
    };

    for (const auto& prop : cnxn_props) {
        std::string value = std::string(prop) + "=" + android::base::GetProperty(prop, "");
        connection_properties.push_back(value);
    }
#endif

    connection_properties.push_back(android::base::StringPrintf(
        "features=%s", FeatureSetToString(supported_features()).c_str()));

    return android::base::StringPrintf(
        "%s::%s", adb_device_banner,
        android::base::Join(connection_properties, ';').c_str());
}

void send_connect(atransport* t) {
    D("Calling send_connect");
    apacket* cp = get_apacket();
    cp->msg.command = A_CNXN;
    // Send the max supported version, but because the transport is
    // initialized to A_VERSION_MIN, this will be compatible with every
    // device.
    cp->msg.arg0 = A_VERSION;
    cp->msg.arg1 = t->get_max_payload();

    std::string connection_str = get_connection_string();
    // Connect and auth packets are limited to MAX_PAYLOAD_V1 because we don't
    // yet know how much data the other size is willing to accept.
    if (connection_str.length() > MAX_PAYLOAD_V1) {
        LOG(FATAL) << "Connection banner is too long (length = "
                   << connection_str.length() << ")";
    }

    cp->payload = std::move(connection_str);
    cp->msg.data_length = cp->payload.size();

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

void parse_banner(const std::string& banner, atransport* t) {
    D("parse_banner: %s", banner.c_str());

    // The format is something like:
    // "device::ro.product.name=x;ro.product.model=y;ro.product.device=z;".
    std::vector<std::string> pieces = android::base::Split(banner, ":");

    // Reset the features list or else if the server sends no features we may
    // keep the existing feature set (http://b/24405971).
    t->SetFeatures("");

    if (pieces.size() > 2) {
        const std::string& props = pieces[2];
        for (const auto& prop : android::base::Split(props, ";")) {
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
            } else if (key == "features") {
                t->SetFeatures(value);
            }
        }
    }

    const std::string& type = pieces[0];
    if (type == "bootloader") {
        D("setting connection_state to kCsBootloader");
        t->SetConnectionState(kCsBootloader);
    } else if (type == "device") {
        D("setting connection_state to kCsDevice");
        t->SetConnectionState(kCsDevice);
    } else if (type == "recovery") {
        D("setting connection_state to kCsRecovery");
        t->SetConnectionState(kCsRecovery);
    } else if (type == "sideload") {
        D("setting connection_state to kCsSideload");
        t->SetConnectionState(kCsSideload);
    } else {
        D("setting connection_state to kCsHost");
        t->SetConnectionState(kCsHost);
    }
}

static void handle_new_connection(atransport* t, apacket* p) {
    if (t->GetConnectionState() != kCsOffline) {
        t->SetConnectionState(kCsOffline);
        handle_offline(t);
    }

    t->update_version(p->msg.arg0, p->msg.arg1);
    parse_banner(p->payload, t);

#if ADB_HOST
    handle_online(t);
#else
    if (!auth_required) {
        handle_online(t);
        send_connect(t);
    } else {
        send_auth_request(t);
    }
#endif

    update_transports();
}

void handle_packet(apacket *p, atransport *t)
{
    D("handle_packet() %c%c%c%c", ((char*) (&(p->msg.command)))[0],
            ((char*) (&(p->msg.command)))[1],
            ((char*) (&(p->msg.command)))[2],
            ((char*) (&(p->msg.command)))[3]);
    print_packet("recv", p);
    CHECK_EQ(p->payload.size(), p->msg.data_length);

    switch(p->msg.command){
    case A_SYNC:
        if (p->msg.arg0){
            send_packet(p, t);
#if ADB_HOST
            send_connect(t);
#endif
        } else {
            t->SetConnectionState(kCsOffline);
            handle_offline(t);
            send_packet(p, t);
        }
        return;

    case A_CNXN:  // CONNECT(version, maxdata, "system-id-string")
        handle_new_connection(t, p);
        break;

    case A_AUTH:
        switch (p->msg.arg0) {
#if ADB_HOST
            case ADB_AUTH_TOKEN:
                if (t->GetConnectionState() == kCsOffline) {
                    t->SetConnectionState(kCsUnauthorized);
                }
                send_auth_response(p->payload.data(), p->msg.data_length, t);
                break;
#else
            case ADB_AUTH_SIGNATURE:
                if (adbd_auth_verify(t->token, sizeof(t->token), p->payload)) {
                    adbd_auth_verified(t);
                    t->failed_auth_attempts = 0;
                } else {
                    if (t->failed_auth_attempts++ > 256) std::this_thread::sleep_for(1s);
                    send_auth_request(t);
                }
                break;

            case ADB_AUTH_RSAPUBLICKEY:
                adbd_auth_confirm_key(p->payload.data(), p->msg.data_length, t);
                break;
#endif
            default:
                t->SetConnectionState(kCsOffline);
                handle_offline(t);
                break;
        }
        break;

    case A_OPEN: /* OPEN(local-id, 0, "destination") */
        if (t->online && p->msg.arg0 != 0 && p->msg.arg1 == 0) {
            asocket* s = create_local_service_socket(p->payload.c_str(), t);
            if (s == nullptr) {
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
            asocket* s = find_local_socket(p->msg.arg1, 0);
            if (s) {
                if(s->peer == 0) {
                    /* On first READY message, create the connection. */
                    s->peer = create_remote_socket(p->msg.arg0, t);
                    s->peer->peer = s;
                    s->ready(s);
                } else if (s->peer->id == p->msg.arg0) {
                    /* Other READY messages must use the same local-id */
                    s->ready(s);
                } else {
                    D("Invalid A_OKAY(%d,%d), expected A_OKAY(%d,%d) on transport %s",
                      p->msg.arg0, p->msg.arg1, s->peer->id, p->msg.arg1, t->serial);
                }
            } else {
                // When receiving A_OKAY from device for A_OPEN request, the host server may
                // have closed the local socket because of client disconnection. Then we need
                // to send A_CLSE back to device to close the service on device.
                send_close(p->msg.arg1, p->msg.arg0, t);
            }
        }
        break;

    case A_CLSE: /* CLOSE(local-id, remote-id, "") or CLOSE(0, remote-id, "") */
        if (t->online && p->msg.arg1 != 0) {
            asocket* s = find_local_socket(p->msg.arg1, p->msg.arg0);
            if (s) {
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
                    D("Invalid A_CLSE(0, %u) from transport %s, expected transport %s",
                      p->msg.arg1, t->serial, s->peer->transport->serial);
                } else {
                    s->close(s);
                }
            }
        }
        break;

    case A_WRTE: /* WRITE(local-id, remote-id, <data>) */
        if (t->online && p->msg.arg0 != 0 && p->msg.arg1 != 0) {
            asocket* s = find_local_socket(p->msg.arg1, p->msg.arg0);
            if (s) {
                unsigned rid = p->msg.arg0;
                if (s->enqueue(s, std::move(p->payload)) == 0) {
                    D("Enqueue the socket");
                    send_ready(s->id, rid, t);
                }
            }
        }
        break;

    default:
        printf("handle_packet: what is %08x?!\n", p->msg.command);
    }

    put_apacket(p);
}

#if ADB_HOST

#ifdef _WIN32

// Try to make a handle non-inheritable and if there is an error, don't output
// any error info, but leave GetLastError() for the caller to read. This is
// convenient if the caller is expecting that this may fail and they'd like to
// ignore such a failure.
static bool _try_make_handle_noninheritable(HANDLE h) {
    if (h != INVALID_HANDLE_VALUE && h != NULL) {
        return SetHandleInformation(h, HANDLE_FLAG_INHERIT, 0) ? true : false;
    }

    return true;
}

// Try to make a handle non-inheritable with the expectation that this should
// succeed, so if this fails, output error info.
static bool _make_handle_noninheritable(HANDLE h) {
    if (!_try_make_handle_noninheritable(h)) {
        // Show the handle value to give us a clue in case we have problems
        // with pseudo-handle values.
        fprintf(stderr, "adb: cannot make handle 0x%p non-inheritable: %s\n", h,
                android::base::SystemErrorCodeToString(GetLastError()).c_str());
        return false;
    }

    return true;
}

// Create anonymous pipe, preventing inheritance of the read pipe and setting
// security of the write pipe to sa.
static bool _create_anonymous_pipe(unique_handle* pipe_read_out,
                                   unique_handle* pipe_write_out,
                                   SECURITY_ATTRIBUTES* sa) {
    HANDLE pipe_read_raw = NULL;
    HANDLE pipe_write_raw = NULL;
    if (!CreatePipe(&pipe_read_raw, &pipe_write_raw, sa, 0)) {
        fprintf(stderr, "adb: CreatePipe failed: %s\n",
                android::base::SystemErrorCodeToString(GetLastError()).c_str());
        return false;
    }

    unique_handle pipe_read(pipe_read_raw);
    pipe_read_raw = NULL;
    unique_handle pipe_write(pipe_write_raw);
    pipe_write_raw = NULL;

    if (!_make_handle_noninheritable(pipe_read.get())) {
        return false;
    }

    *pipe_read_out = std::move(pipe_read);
    *pipe_write_out = std::move(pipe_write);

    return true;
}

// Read from a pipe (that we take ownership of) and write the result to stdout/stderr. Return on
// error or when the pipe is closed. Internally makes inheritable handles, so this should not be
// called if subprocesses may be started concurrently.
static unsigned _redirect_pipe_thread(HANDLE h, DWORD nStdHandle) {
    // Take ownership of the HANDLE and close when we're done.
    unique_handle   read_pipe(h);
    const char*     output_name = nStdHandle == STD_OUTPUT_HANDLE ? "stdout" : "stderr";
    const int       original_fd = fileno(nStdHandle == STD_OUTPUT_HANDLE ? stdout : stderr);
    std::unique_ptr<FILE, decltype(&fclose)> stream(nullptr, fclose);

    if (original_fd == -1) {
        fprintf(stderr, "adb: failed to get file descriptor for %s: %s\n", output_name,
                strerror(errno));
        return EXIT_FAILURE;
    }

    // If fileno() is -2, stdout/stderr is not associated with an output stream, so we should read,
    // but don't write. Otherwise, make a FILE* identical to stdout/stderr except that it is in
    // binary mode with no CR/LR translation since we're reading raw.
    if (original_fd >= 0) {
        // This internally makes a duplicate file handle that is inheritable, so callers should not
        // call this function if subprocesses may be started concurrently.
        const int fd = dup(original_fd);
        if (fd == -1) {
            fprintf(stderr, "adb: failed to duplicate file descriptor for %s: %s\n", output_name,
                    strerror(errno));
            return EXIT_FAILURE;
        }

        // Note that although we call fdopen() below with a binary flag, it may not adhere to that
        // flag, so we have to set the mode manually.
        if (_setmode(fd, _O_BINARY) == -1) {
            fprintf(stderr, "adb: failed to set binary mode for duplicate of %s: %s\n", output_name,
                    strerror(errno));
            unix_close(fd);
            return EXIT_FAILURE;
        }

        stream.reset(fdopen(fd, "wb"));
        if (stream.get() == nullptr) {
            fprintf(stderr, "adb: failed to open duplicate stream for %s: %s\n", output_name,
                    strerror(errno));
            unix_close(fd);
            return EXIT_FAILURE;
        }

        // Unbuffer the stream because it will be buffered by default and we want subprocess output
        // to be shown immediately.
        if (setvbuf(stream.get(), NULL, _IONBF, 0) == -1) {
            fprintf(stderr, "adb: failed to unbuffer %s: %s\n", output_name, strerror(errno));
            return EXIT_FAILURE;
        }

        // fd will be closed when stream is closed.
    }

    while (true) {
        char    buf[64 * 1024];
        DWORD   bytes_read = 0;
        if (!ReadFile(read_pipe.get(), buf, sizeof(buf), &bytes_read, NULL)) {
            const DWORD err = GetLastError();
            // ERROR_BROKEN_PIPE is expected when the subprocess closes
            // the other end of the pipe.
            if (err == ERROR_BROKEN_PIPE) {
                return EXIT_SUCCESS;
            } else {
                fprintf(stderr, "adb: failed to read from %s: %s\n", output_name,
                        android::base::SystemErrorCodeToString(err).c_str());
                return EXIT_FAILURE;
            }
        }

        // Don't try to write if our stdout/stderr was not setup by the parent process.
        if (stream) {
            // fwrite() actually calls adb_fwrite() which can write UTF-8 to the console.
            const size_t bytes_written = fwrite(buf, 1, bytes_read, stream.get());
            if (bytes_written != bytes_read) {
                fprintf(stderr, "adb: error: only wrote %zu of %lu bytes to %s\n", bytes_written,
                        bytes_read, output_name);
                return EXIT_FAILURE;
            }
        }
    }
}

static unsigned __stdcall _redirect_stdout_thread(HANDLE h) {
    adb_thread_setname("stdout redirect");
    return _redirect_pipe_thread(h, STD_OUTPUT_HANDLE);
}

static unsigned __stdcall _redirect_stderr_thread(HANDLE h) {
    adb_thread_setname("stderr redirect");
    return _redirect_pipe_thread(h, STD_ERROR_HANDLE);
}

#endif

static void ReportServerStartupFailure(pid_t pid) {
    fprintf(stderr, "ADB server didn't ACK\n");
    fprintf(stderr, "Full server startup log: %s\n", GetLogFilePath().c_str());
    fprintf(stderr, "Server had pid: %d\n", pid);

    unique_fd fd(adb_open(GetLogFilePath().c_str(), O_RDONLY));
    if (fd == -1) return;

    // Let's not show more than 128KiB of log...
    adb_lseek(fd, -128 * 1024, SEEK_END);
    std::string content;
    if (!android::base::ReadFdToString(fd, &content)) return;

    std::string header = android::base::StringPrintf("--- adb starting (pid %d) ---", pid);
    std::vector<std::string> lines = android::base::Split(content, "\n");
    int i = lines.size() - 1;
    while (i >= 0 && lines[i] != header) --i;
    while (static_cast<size_t>(i) < lines.size()) fprintf(stderr, "%s\n", lines[i++].c_str());
}

int launch_server(const std::string& socket_spec) {
#if defined(_WIN32)
    /* we need to start the server in the background                    */
    /* we create a PIPE that will be used to wait for the server's "OK" */
    /* message since the pipe handles must be inheritable, we use a     */
    /* security attribute                                               */
    SECURITY_ATTRIBUTES   sa;
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;

    // Redirect stdin to Windows /dev/null. If we instead pass an original
    // stdin/stdout/stderr handle and it is a console handle, when the adb
    // server starts up, the C Runtime will see a console handle for a process
    // that isn't connected to a console and it will configure
    // stdin/stdout/stderr to be closed. At that point, freopen() could be used
    // to reopen stderr/out, but it would take more massaging to fixup the file
    // descriptor number that freopen() uses. It's simplest to avoid all of this
    // complexity by just redirecting stdin to `nul' and then the C Runtime acts
    // as expected.
    unique_handle   nul_read(CreateFileW(L"nul", GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL, NULL));
    if (nul_read.get() == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "adb: CreateFileW 'nul' failed: %s\n",
                android::base::SystemErrorCodeToString(GetLastError()).c_str());
        return -1;
    }

    // Create pipes with non-inheritable read handle, inheritable write handle. We need to connect
    // the subprocess to pipes instead of just letting the subprocess inherit our existing
    // stdout/stderr handles because a DETACHED_PROCESS cannot write to a console that it is not
    // attached to.
    unique_handle   ack_read, ack_write;
    if (!_create_anonymous_pipe(&ack_read, &ack_write, &sa)) {
        return -1;
    }
    unique_handle   stdout_read, stdout_write;
    if (!_create_anonymous_pipe(&stdout_read, &stdout_write, &sa)) {
        return -1;
    }
    unique_handle   stderr_read, stderr_write;
    if (!_create_anonymous_pipe(&stderr_read, &stderr_write, &sa)) {
        return -1;
    }

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
     * Note that even if we don't pass these handles in the STARTUPINFO struct,
     * if they're marked inheritable, they're still inherited, requiring us to
     * deal with this.
     *
     * If we're still having problems with inheriting random handles in the
     * future, consider using PROC_THREAD_ATTRIBUTE_HANDLE_LIST to explicitly
     * specify which handles should be inherited: http://blogs.msdn.com/b/oldnewthing/archive/2011/12/16/10248328.aspx
     *
     * Older versions of Windows return console pseudo-handles that cannot be
     * made non-inheritable, so ignore those failures.
     */
    _try_make_handle_noninheritable(GetStdHandle(STD_INPUT_HANDLE));
    _try_make_handle_noninheritable(GetStdHandle(STD_OUTPUT_HANDLE));
    _try_make_handle_noninheritable(GetStdHandle(STD_ERROR_HANDLE));

    STARTUPINFOW    startup;
    ZeroMemory( &startup, sizeof(startup) );
    startup.cb = sizeof(startup);
    startup.hStdInput  = nul_read.get();
    startup.hStdOutput = stdout_write.get();
    startup.hStdError  = stderr_write.get();
    startup.dwFlags    = STARTF_USESTDHANDLES;

    // Verify that the pipe_write handle value can be passed on the command line
    // as %d and that the rest of adb code can pass it around in an int.
    const int ack_write_as_int = cast_handle_to_int(ack_write.get());
    if (cast_int_to_handle(ack_write_as_int) != ack_write.get()) {
        // If this fires, either handle values are larger than 32-bits or else
        // there is a bug in our casting.
        // https://msdn.microsoft.com/en-us/library/windows/desktop/aa384203%28v=vs.85%29.aspx
        fprintf(stderr, "adb: cannot fit pipe handle value into 32-bits: 0x%p\n", ack_write.get());
        return -1;
    }

    // get path of current program
    WCHAR       program_path[MAX_PATH];
    const DWORD module_result = GetModuleFileNameW(NULL, program_path,
                                                   arraysize(program_path));
    if ((module_result >= arraysize(program_path)) || (module_result == 0)) {
        // String truncation or some other error.
        fprintf(stderr, "adb: cannot get executable path: %s\n",
                android::base::SystemErrorCodeToString(GetLastError()).c_str());
        return -1;
    }

    WCHAR   args[64];
    snwprintf(args, arraysize(args), L"adb -L %s fork-server server --reply-fd %d",
              socket_spec.c_str(), ack_write_as_int);

    PROCESS_INFORMATION   pinfo;
    ZeroMemory(&pinfo, sizeof(pinfo));

    if (!CreateProcessW(
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
            &pinfo )) {
        fprintf(stderr, "adb: CreateProcessW failed: %s\n",
                android::base::SystemErrorCodeToString(GetLastError()).c_str());
        return -1;
    }

    unique_handle   process_handle(pinfo.hProcess);
    pinfo.hProcess = NULL;

    // Close handles that we no longer need to complete the rest.
    CloseHandle(pinfo.hThread);
    pinfo.hThread = NULL;

    nul_read.reset();
    ack_write.reset();
    stdout_write.reset();
    stderr_write.reset();

    // Start threads to read from subprocess stdout/stderr and write to ours to make subprocess
    // errors easier to diagnose. Note that the threads internally create inheritable handles, but
    // that is ok because we've already spawned the subprocess.

    // In the past, reading from a pipe before the child process's C Runtime
    // started up and called GetFileType() caused a hang: http://blogs.msdn.com/b/oldnewthing/archive/2011/12/02/10243553.aspx#10244216
    // This is reportedly fixed in Windows Vista: https://support.microsoft.com/en-us/kb/2009703
    // I was unable to reproduce the problem on Windows XP. It sounds like a
    // Windows Update may have fixed this: https://www.duckware.com/tech/peeknamedpipe.html
    unique_handle   stdout_thread(reinterpret_cast<HANDLE>(
            _beginthreadex(NULL, 0, _redirect_stdout_thread, stdout_read.get(),
                           0, NULL)));
    if (stdout_thread.get() == nullptr) {
        fprintf(stderr, "adb: cannot create thread: %s\n", strerror(errno));
        return -1;
    }
    stdout_read.release();  // Transfer ownership to new thread

    unique_handle   stderr_thread(reinterpret_cast<HANDLE>(
            _beginthreadex(NULL, 0, _redirect_stderr_thread, stderr_read.get(),
                           0, NULL)));
    if (stderr_thread.get() == nullptr) {
        fprintf(stderr, "adb: cannot create thread: %s\n", strerror(errno));
        return -1;
    }
    stderr_read.release();  // Transfer ownership to new thread

    bool    got_ack = false;

    // Wait for the "OK\n" message, for the pipe to be closed, or other error.
    {
        char    temp[3];
        DWORD   count = 0;

        if (ReadFile(ack_read.get(), temp, sizeof(temp), &count, NULL)) {
            const CHAR  expected[] = "OK\n";
            const DWORD expected_length = arraysize(expected) - 1;
            if (count == expected_length &&
                memcmp(temp, expected, expected_length) == 0) {
                got_ack = true;
            } else {
                ReportServerStartupFailure(GetProcessId(process_handle.get()));
                return -1;
            }
        } else {
            const DWORD err = GetLastError();
            // If the ACK was not written and the process exited, GetLastError()
            // is probably ERROR_BROKEN_PIPE, in which case that info is not
            // useful to the user.
            fprintf(stderr, "could not read ok from ADB Server%s\n",
                    err == ERROR_BROKEN_PIPE ? "" :
                    android::base::StringPrintf(": %s",
                            android::base::SystemErrorCodeToString(err).c_str()).c_str());
        }
    }

    // Always try to wait a bit for threads reading stdout/stderr to finish.
    // If the process started ok, it should close the pipes causing the threads
    // to finish. If the process had an error, it should exit, also causing
    // the pipes to be closed. In that case we want to read all of the output
    // and write it out so that the user can diagnose failures.
    const DWORD     thread_timeout_ms = 15 * 1000;
    const HANDLE    threads[] = { stdout_thread.get(), stderr_thread.get() };
    const DWORD     wait_result = WaitForMultipleObjects(arraysize(threads),
            threads, TRUE, thread_timeout_ms);
    if (wait_result == WAIT_TIMEOUT) {
        // Threads did not finish after waiting a little while. Perhaps the
        // server didn't close pipes, or it is hung.
        fprintf(stderr, "adb: timed out waiting for threads to finish reading from ADB server\n");
        // Process handles are signaled when the process exits, so if we wait
        // on the handle for 0 seconds and it returns 'timeout', that means that
        // the process is still running.
        if (WaitForSingleObject(process_handle.get(), 0) == WAIT_TIMEOUT) {
            // We could TerminateProcess(), but that seems somewhat presumptive.
            fprintf(stderr, "adb: server is running with process id %lu\n", pinfo.dwProcessId);
        }
        return -1;
    }

    if (wait_result != WAIT_OBJECT_0) {
        fprintf(stderr, "adb: unexpected result waiting for threads: %lu: %s\n", wait_result,
                android::base::SystemErrorCodeToString(GetLastError()).c_str());
        return -1;
    }

    // For now ignore the thread exit codes and assume they worked properly.

    if (!got_ack) {
        return -1;
    }
#else /* !defined(_WIN32) */
    // set up a pipe so the child can tell us when it is ready.
    // fd[0] will be parent's end, and the child will write on fd[1]
    int fd[2];
    if (pipe(fd)) {
        fprintf(stderr, "pipe failed in launch_server, errno: %d\n", errno);
        return -1;
    }

    std::string path = android::base::GetExecutablePath();

    pid_t pid = fork();
    if (pid < 0) return -1;

    if (pid == 0) {
        // child side of the fork

        adb_close(fd[0]);

        char reply_fd[30];
        snprintf(reply_fd, sizeof(reply_fd), "%d", fd[1]);
        // child process
        int result = execl(path.c_str(), "adb", "-L", socket_spec.c_str(), "fork-server", "server",
                           "--reply-fd", reply_fd, NULL);
        // this should not return
        fprintf(stderr, "adb: execl returned %d: %s\n", result, strerror(errno));
    } else {
        // parent side of the fork
        char temp[3] = {};
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
            ReportServerStartupFailure(pid);
            return -1;
        }
    }
#endif /* !defined(_WIN32) */
    return 0;
}
#endif /* ADB_HOST */

// Try to handle a network forwarding request.
// This returns 1 on success, 0 on failure, and -1 to indicate this is not
// a forwarding-related request.
int handle_forward_request(const char* service, atransport* transport, int reply_fd) {
    if (!strcmp(service, "list-forward")) {
        // Create the list of forward redirections.
        std::string listeners = format_listeners();
#if ADB_HOST
        SendOkay(reply_fd);
#endif
        return SendProtocolString(reply_fd, listeners);
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

    if (!strncmp(service, "forward:", 8) || !strncmp(service, "killforward:", 12)) {
        // killforward:local
        // forward:(norebind:)?local;remote
        bool kill_forward = false;
        bool no_rebind = false;
        if (android::base::StartsWith(service, "killforward:")) {
            kill_forward = true;
            service += 12;
        } else {
            service += 8;   // skip past "forward:"
            if (android::base::StartsWith(service, "norebind:")) {
                no_rebind = true;
                service += 9;
            }
        }

        std::vector<std::string> pieces = android::base::Split(service, ";");

        if (kill_forward) {
            // Check killforward: parameter format: '<local>'
            if (pieces.size() != 1 || pieces[0].empty()) {
                SendFail(reply_fd, android::base::StringPrintf("bad killforward: %s", service));
                return 1;
            }
        } else {
            // Check forward: parameter format: '<local>;<remote>'
            if (pieces.size() != 2 || pieces[0].empty() || pieces[1].empty() || pieces[1][0] == '*') {
                SendFail(reply_fd, android::base::StringPrintf("bad forward: %s", service));
                return 1;
            }
        }

        std::string error;
        InstallStatus r;
        int resolved_tcp_port = 0;
        if (kill_forward) {
            r = remove_listener(pieces[0].c_str(), transport);
        } else {
            r = install_listener(pieces[0], pieces[1].c_str(), transport, no_rebind,
                                 &resolved_tcp_port, &error);
        }
        if (r == INSTALL_STATUS_OK) {
#if ADB_HOST
            // On the host: 1st OKAY is connect, 2nd OKAY is status.
            SendOkay(reply_fd);
#endif
            SendOkay(reply_fd);

            // If a TCP port was resolved, send the actual port number back.
            if (resolved_tcp_port != 0) {
                SendProtocolString(reply_fd, android::base::StringPrintf("%d", resolved_tcp_port));
            }

            return 1;
        }

        std::string message;
        switch (r) {
          case INSTALL_STATUS_OK: message = "success (!)"; break;
          case INSTALL_STATUS_INTERNAL_ERROR: message = "internal error"; break;
          case INSTALL_STATUS_CANNOT_BIND:
            message = android::base::StringPrintf("cannot bind listener: %s",
                                                  error.c_str());
            break;
          case INSTALL_STATUS_CANNOT_REBIND:
            message = android::base::StringPrintf("cannot rebind existing socket");
            break;
          case INSTALL_STATUS_LISTENER_NOT_FOUND:
            message = android::base::StringPrintf("listener '%s' not found", service);
            break;
        }
        SendFail(reply_fd, message);
        return 1;
    }
    return 0;
}

#if ADB_HOST
static int SendOkay(int fd, const std::string& s) {
    SendOkay(fd);
    SendProtocolString(fd, s);
    return 0;
}

int handle_host_request(const char* service, TransportType type, const char* serial,
                        TransportId transport_id, int reply_fd, asocket* s) {
    if (strcmp(service, "kill") == 0) {
        fprintf(stderr, "adb server killed by remote request\n");
        fflush(stdout);

        // Send a reply even though we don't read it anymore, so that old versions
        // of adb that do read it don't spew error messages.
        SendOkay(reply_fd);

        // Rely on process exit to close the socket for us.
        exit(0);
    }

    // "transport:" is used for switching transport with a specified serial number
    // "transport-usb:" is used for switching transport to the only USB transport
    // "transport-local:" is used for switching transport to the only local transport
    // "transport-any:" is used for switching transport to the only transport
    if (!strncmp(service, "transport", strlen("transport"))) {
        TransportType type = kTransportAny;

        if (!strncmp(service, "transport-id:", strlen("transport-id:"))) {
            service += strlen("transport-id:");
            transport_id = strtoll(service, const_cast<char**>(&service), 10);
            if (*service != '\0') {
                SendFail(reply_fd, "invalid transport id");
                return 1;
            }
        } else if (!strncmp(service, "transport-usb", strlen("transport-usb"))) {
            type = kTransportUsb;
        } else if (!strncmp(service, "transport-local", strlen("transport-local"))) {
            type = kTransportLocal;
        } else if (!strncmp(service, "transport-any", strlen("transport-any"))) {
            type = kTransportAny;
        } else if (!strncmp(service, "transport:", strlen("transport:"))) {
            service += strlen("transport:");
            serial = service;
        }

        std::string error;
        atransport* t = acquire_one_transport(type, serial, transport_id, nullptr, &error);
        if (t != nullptr) {
            s->transport = t;
            SendOkay(reply_fd);
        } else {
            SendFail(reply_fd, error);
        }
        return 1;
    }

    // return a list of all connected devices
    if (!strncmp(service, "devices", 7)) {
        bool long_listing = (strcmp(service+7, "-l") == 0);
        if (long_listing || service[7] == 0) {
            D("Getting device list...");
            std::string device_list = list_transports(long_listing);
            D("Sending device list...");
            return SendOkay(reply_fd, device_list);
        }
        return 1;
    }

    if (!strcmp(service, "reconnect-offline")) {
        std::string response;
        close_usb_devices([&response](const atransport* transport) {
            switch (transport->GetConnectionState()) {
                case kCsOffline:
                case kCsUnauthorized:
                    response += "reconnecting " + transport->serial_name() + "\n";
                    return true;
                default:
                    return false;
            }
        });
        if (!response.empty()) {
            response.resize(response.size() - 1);
        }
        SendOkay(reply_fd, response);
        return 0;
    }

    if (!strcmp(service, "features")) {
        std::string error;
        atransport* t = acquire_one_transport(type, serial, transport_id, nullptr, &error);
        if (t != nullptr) {
            SendOkay(reply_fd, FeatureSetToString(t->features()));
        } else {
            SendFail(reply_fd, error);
        }
        return 0;
    }

    if (!strcmp(service, "host-features")) {
        FeatureSet features = supported_features();
        // Abuse features to report libusb status.
        if (should_use_libusb()) {
            features.insert(kFeatureLibusb);
        }
        features.insert(kFeaturePushSync);
        SendOkay(reply_fd, FeatureSetToString(features));
        return 0;
    }

    // remove TCP transport
    if (!strncmp(service, "disconnect:", 11)) {
        const std::string address(service + 11);
        if (address.empty()) {
            kick_all_tcp_devices();
            return SendOkay(reply_fd, "disconnected everything");
        }

        std::string serial;
        std::string host;
        int port = DEFAULT_ADB_LOCAL_TRANSPORT_PORT;
        std::string error;
        if (!android::base::ParseNetAddress(address, &host, &port, &serial, &error)) {
            return SendFail(reply_fd, android::base::StringPrintf("couldn't parse '%s': %s",
                                                                  address.c_str(), error.c_str()));
        }
        atransport* t = find_transport(serial.c_str());
        if (t == nullptr) {
            return SendFail(reply_fd, android::base::StringPrintf("no such device '%s'",
                                                                  serial.c_str()));
        }
        kick_transport(t);
        return SendOkay(reply_fd, android::base::StringPrintf("disconnected %s", address.c_str()));
    }

    // Returns our value for ADB_SERVER_VERSION.
    if (!strcmp(service, "version")) {
        return SendOkay(reply_fd, android::base::StringPrintf("%04x", ADB_SERVER_VERSION));
    }

    // These always report "unknown" rather than the actual error, for scripts.
    if (!strcmp(service, "get-serialno")) {
        std::string error;
        atransport* t = acquire_one_transport(type, serial, transport_id, nullptr, &error);
        if (t) {
            return SendOkay(reply_fd, t->serial ? t->serial : "unknown");
        } else {
            return SendFail(reply_fd, error);
        }
    }
    if (!strcmp(service, "get-devpath")) {
        std::string error;
        atransport* t = acquire_one_transport(type, serial, transport_id, nullptr, &error);
        if (t) {
            return SendOkay(reply_fd, t->devpath ? t->devpath : "unknown");
        } else {
            return SendFail(reply_fd, error);
        }
    }
    if (!strcmp(service, "get-state")) {
        std::string error;
        atransport* t = acquire_one_transport(type, serial, transport_id, nullptr, &error);
        if (t) {
            return SendOkay(reply_fd, t->connection_state_name());
        } else {
            return SendFail(reply_fd, error);
        }
    }

    // Indicates a new emulator instance has started.
    if (!strncmp(service, "emulator:", 9)) {
        int  port = atoi(service+9);
        local_connect(port);
        /* we don't even need to send a reply */
        return 0;
    }

    if (!strcmp(service, "reconnect")) {
        std::string response;
        atransport* t = acquire_one_transport(type, serial, transport_id, nullptr, &response, true);
        if (t != nullptr) {
            kick_transport(t);
            response =
                "reconnecting " + t->serial_name() + " [" + t->connection_state_name() + "]\n";
        }
        return SendOkay(reply_fd, response);
    }

    std::string error;
    atransport* t = acquire_one_transport(type, serial, transport_id, nullptr, &error);
    if (!t) {
        return -1;
    }

    int ret = handle_forward_request(service, t, reply_fd);
    if (ret >= 0)
      return ret - 1;
    return -1;
}

static auto& init_mutex = *new std::mutex();
static auto& init_cv = *new std::condition_variable();
static bool device_scan_complete = false;
static bool transports_ready = false;

void update_transport_status() {
    bool result = iterate_transports([](const atransport* t) {
        if (t->type == kTransportUsb && t->online != 1) {
            return false;
        }
        return true;
    });

    bool ready;
    {
        std::lock_guard<std::mutex> lock(init_mutex);
        transports_ready = result;
        ready = transports_ready && device_scan_complete;
    }

    if (ready) {
        init_cv.notify_all();
    }
}

void adb_notify_device_scan_complete() {
    {
        std::lock_guard<std::mutex> lock(init_mutex);
        if (device_scan_complete) {
            return;
        }

        device_scan_complete = true;
    }

    update_transport_status();
}

void adb_wait_for_device_initialization() {
    std::unique_lock<std::mutex> lock(init_mutex);
    init_cv.wait_for(lock, 3s, []() { return device_scan_complete && transports_ready; });
}

#endif  // ADB_HOST

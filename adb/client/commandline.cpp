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

#include <memory>
#include <string>
#include <thread>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>

#if !defined(_WIN32)
#include <signal.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>
#endif

#include "adb.h"
#include "adb_auth.h"
#include "adb_client.h"
#include "adb_io.h"
#include "adb_unique_fd.h"
#include "adb_utils.h"
#include "bugreport.h"
#include "commandline.h"
#include "file_sync_service.h"
#include "services.h"
#include "shell_service.h"
#include "sysdeps/chrono.h"

static int install_app(int argc, const char** argv);
static int install_multiple_app(int argc, const char** argv);
static int uninstall_app(int argc, const char** argv);
static int install_app_legacy(int argc, const char** argv);
static int uninstall_app_legacy(int argc, const char** argv);

extern int gListenAll;

DefaultStandardStreamsCallback DEFAULT_STANDARD_STREAMS_CALLBACK(nullptr, nullptr);

static std::string product_file(const char* file) {
    const char* ANDROID_PRODUCT_OUT = getenv("ANDROID_PRODUCT_OUT");
    if (ANDROID_PRODUCT_OUT == nullptr) {
        fprintf(stderr, "adb: product directory not specified; set $ANDROID_PRODUCT_OUT\n");
        exit(1);
    }
    return android::base::StringPrintf("%s%s%s", ANDROID_PRODUCT_OUT, OS_PATH_SEPARATOR_STR, file);
}

static void help() {
    fprintf(stdout, "%s\n", adb_version().c_str());
    // clang-format off
    fprintf(stdout,
        "global options:\n"
        " -a         listen on all network interfaces, not just localhost\n"
        " -d         use USB device (error if multiple devices connected)\n"
        " -e         use TCP/IP device (error if multiple TCP/IP devices available)\n"
        " -s SERIAL  use device with given serial (overrides $ANDROID_SERIAL)\n"
        " -t ID      use device with given transport id\n"
        " -H         name of adb server host [default=localhost]\n"
        " -P         port of adb server [default=5037]\n"
        " -L SOCKET  listen on given socket for adb server [default=tcp:localhost:5037]\n"
        "\n"
        "general commands:\n"
        " devices [-l]             list connected devices (-l for long output)\n"
        " help                     show this help message\n"
        " version                  show version num\n"
        "\n"
        "networking:\n"
        " connect HOST[:PORT]      connect to a device via TCP/IP [default port=5555]\n"
        " disconnect [HOST[:PORT]]\n"
        "     disconnect from given TCP/IP device [default port=5555], or all\n"
        " forward --list           list all forward socket connections\n"
        " forward [--no-rebind] LOCAL REMOTE\n"
        "     forward socket connection using:\n"
        "       tcp:<port> (<local> may be \"tcp:0\" to pick any open port)\n"
        "       localabstract:<unix domain socket name>\n"
        "       localreserved:<unix domain socket name>\n"
        "       localfilesystem:<unix domain socket name>\n"
        "       dev:<character device name>\n"
        "       jdwp:<process pid> (remote only)\n"
        " forward --remove LOCAL   remove specific forward socket connection\n"
        " forward --remove-all     remove all forward socket connections\n"
        " ppp TTY [PARAMETER...]   run PPP over USB\n"
        " reverse --list           list all reverse socket connections from device\n"
        " reverse [--no-rebind] REMOTE LOCAL\n"
        "     reverse socket connection using:\n"
        "       tcp:<port> (<remote> may be \"tcp:0\" to pick any open port)\n"
        "       localabstract:<unix domain socket name>\n"
        "       localreserved:<unix domain socket name>\n"
        "       localfilesystem:<unix domain socket name>\n"
        " reverse --remove REMOTE  remove specific reverse socket connection\n"
        " reverse --remove-all     remove all reverse socket connections from device\n"
        "\n"
        "file transfer:\n"
        " push [--sync] LOCAL... REMOTE\n"
        "     copy local files/directories to device\n"
        "     --sync: only push files that are newer on the host than the device\n"
        " pull [-a] REMOTE... LOCAL\n"
        "     copy files/dirs from device\n"
        "     -a: preserve file timestamp and mode\n"
        " sync [system|vendor|oem|data|all]\n"
        "     sync a local build from $ANDROID_PRODUCT_OUT to the device (default all)\n"
        "     -l: list but don't copy\n"
        "\n"
        "shell:\n"
        " shell [-e ESCAPE] [-n] [-Tt] [-x] [COMMAND...]\n"
        "     run remote shell command (interactive shell if no command given)\n"
        "     -e: choose escape character, or \"none\"; default '~'\n"
        "     -n: don't read from stdin\n"
        "     -T: disable PTY allocation\n"
        "     -t: force PTY allocation\n"
        "     -x: disable remote exit codes and stdout/stderr separation\n"
        " emu COMMAND              run emulator console command\n"
        "\n"
        "app installation:\n"
        " install [-lrtsdg] PACKAGE\n"
        " install-multiple [-lrtsdpg] PACKAGE...\n"
        "     push package(s) to the device and install them\n"
        "     -l: forward lock application\n"
        "     -r: replace existing application\n"
        "     -t: allow test packages\n"
        "     -s: install application on sdcard\n"
        "     -d: allow version code downgrade (debuggable packages only)\n"
        "     -p: partial application install (install-multiple only)\n"
        "     -g: grant all runtime permissions\n"
        " uninstall [-k] PACKAGE\n"
        "     remove this app package from the device\n"
        "     '-k': keep the data and cache directories\n"
        "\n"
        "backup/restore:\n"
        "   to show usage run \"adb shell bu help\"\n"
        "\n"
        "debugging:\n"
        " bugreport [PATH]\n"
        "     write bugreport to given PATH [default=bugreport.zip];\n"
        "     if PATH is a directory, the bug report is saved in that directory.\n"
        "     devices that don't support zipped bug reports output to stdout.\n"
        " jdwp                     list pids of processes hosting a JDWP transport\n"
        " logcat                   show device log (logcat --help for more)\n"
        "\n"
        "security:\n"
        " disable-verity           disable dm-verity checking on userdebug builds\n"
        " enable-verity            re-enable dm-verity checking on userdebug builds\n"
        " keygen FILE\n"
        "     generate adb public/private key; private key stored in FILE,\n"
        "     public key stored in FILE.pub (existing files overwritten)\n"
        "\n"
        "scripting:\n"
        " wait-for[-TRANSPORT]-STATE\n"
        "     wait for device to be in the given state\n"
        "     State: device, recovery, sideload, or bootloader\n"
        "     Transport: usb, local, or any [default=any]\n"
        " get-state                print offline | bootloader | device\n"
        " get-serialno             print <serial-number>\n"
        " get-devpath              print <device-path>\n"
        " remount\n"
        "     remount /system, /vendor, and /oem partitions read-write\n"
        " reboot [bootloader|recovery|sideload|sideload-auto-reboot]\n"
        "     reboot the device; defaults to booting system image but\n"
        "     supports bootloader and recovery too. sideload reboots\n"
        "     into recovery and automatically starts sideload mode,\n"
        "     sideload-auto-reboot is the same but reboots after sideloading.\n"
        " sideload OTAPACKAGE      sideload the given full OTA package\n"
        " root                     restart adbd with root permissions\n"
        " unroot                   restart adbd without root permissions\n"
        " usb                      restart adb server listening on USB\n"
        " tcpip PORT               restart adb server listening on TCP on PORT\n"
        "\n"
        "internal debugging:\n"
        " start-server             ensure that there is a server running\n"
        " kill-server              kill the server if it is running\n"
        " reconnect                kick connection from host side to force reconnect\n"
        " reconnect device         kick connection from device side to force reconnect\n"
        " reconnect offline        reset offline/unauthorized devices to force reconnect\n"
        "\n"
        "environment variables:\n"
        " $ADB_TRACE\n"
        "     comma-separated list of debug info to log:\n"
        "     all,adb,sockets,packets,rwx,usb,sync,sysdeps,transport,jdwp\n"
        " $ADB_VENDOR_KEYS         colon-separated list of keys (files or directories)\n"
        " $ANDROID_SERIAL          serial number to connect to (see -s)\n"
        " $ANDROID_LOG_TAGS        tags to be used by logcat (see logcat --help)\n");
    // clang-format on
}

#if defined(_WIN32)

// Implemented in sysdeps_win32.cpp.
void stdin_raw_init();
void stdin_raw_restore();

#else
static termios g_saved_terminal_state;

static void stdin_raw_init() {
    if (tcgetattr(STDIN_FILENO, &g_saved_terminal_state)) return;

    termios tio;
    if (tcgetattr(STDIN_FILENO, &tio)) return;

    cfmakeraw(&tio);

    // No timeout but request at least one character per read.
    tio.c_cc[VTIME] = 0;
    tio.c_cc[VMIN] = 1;

    tcsetattr(STDIN_FILENO, TCSAFLUSH, &tio);
}

static void stdin_raw_restore() {
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_saved_terminal_state);
}
#endif

// Reads from |fd| and prints received data. If |use_shell_protocol| is true
// this expects that incoming data will use the shell protocol, in which case
// stdout/stderr are routed independently and the remote exit code will be
// returned.
// if |callback| is non-null, stdout/stderr output will be handled by it.
int read_and_dump(int fd, bool use_shell_protocol = false,
                  StandardStreamsCallbackInterface* callback = &DEFAULT_STANDARD_STREAMS_CALLBACK) {
    int exit_code = 0;
    if (fd < 0) return exit_code;

    std::unique_ptr<ShellProtocol> protocol;
    int length = 0;

    char raw_buffer[BUFSIZ];
    char* buffer_ptr = raw_buffer;
    if (use_shell_protocol) {
        protocol.reset(new ShellProtocol(fd));
        if (!protocol) {
            LOG(ERROR) << "failed to allocate memory for ShellProtocol object";
            return 1;
        }
        buffer_ptr = protocol->data();
    }

    while (true) {
        if (use_shell_protocol) {
            if (!protocol->Read()) {
                break;
            }
            length = protocol->data_length();
            switch (protocol->id()) {
                case ShellProtocol::kIdStdout:
                    callback->OnStdout(buffer_ptr, length);
                    break;
                case ShellProtocol::kIdStderr:
                    callback->OnStderr(buffer_ptr, length);
                    break;
                case ShellProtocol::kIdExit:
                    exit_code = protocol->data()[0];
                    continue;
                default:
                    continue;
            }
            length = protocol->data_length();
        } else {
            D("read_and_dump(): pre adb_read(fd=%d)", fd);
            length = adb_read(fd, raw_buffer, sizeof(raw_buffer));
            D("read_and_dump(): post adb_read(fd=%d): length=%d", fd, length);
            if (length <= 0) {
                break;
            }
            callback->OnStdout(buffer_ptr, length);
        }
    }

    return callback->Done(exit_code);
}

static void read_status_line(int fd, char* buf, size_t count)
{
    count--;
    while (count > 0) {
        int len = adb_read(fd, buf, count);
        if (len <= 0) {
            break;
        }

        buf += len;
        count -= len;
    }
    *buf = '\0';
}

static void stdinout_raw_prologue(int inFd, int outFd, int& old_stdin_mode, int& old_stdout_mode) {
    if (inFd == STDIN_FILENO) {
        stdin_raw_init();
#ifdef _WIN32
        old_stdin_mode = _setmode(STDIN_FILENO, _O_BINARY);
        if (old_stdin_mode == -1) {
            fatal_errno("could not set stdin to binary");
        }
#endif
    }

#ifdef _WIN32
    if (outFd == STDOUT_FILENO) {
        old_stdout_mode = _setmode(STDOUT_FILENO, _O_BINARY);
        if (old_stdout_mode == -1) {
            fatal_errno("could not set stdout to binary");
        }
    }
#endif
}

static void stdinout_raw_epilogue(int inFd, int outFd, int old_stdin_mode, int old_stdout_mode) {
    if (inFd == STDIN_FILENO) {
        stdin_raw_restore();
#ifdef _WIN32
        if (_setmode(STDIN_FILENO, old_stdin_mode) == -1) {
            fatal_errno("could not restore stdin mode");
        }
#endif
    }

#ifdef _WIN32
    if (outFd == STDOUT_FILENO) {
        if (_setmode(STDOUT_FILENO, old_stdout_mode) == -1) {
            fatal_errno("could not restore stdout mode");
        }
    }
#endif
}

static void copy_to_file(int inFd, int outFd) {
    const size_t BUFSIZE = 32 * 1024;
    char* buf = (char*) malloc(BUFSIZE);
    if (buf == nullptr) fatal("couldn't allocate buffer for copy_to_file");
    int len;
    long total = 0;
    int old_stdin_mode = -1;
    int old_stdout_mode = -1;

    D("copy_to_file(%d -> %d)", inFd, outFd);

    stdinout_raw_prologue(inFd, outFd, old_stdin_mode, old_stdout_mode);

    while (true) {
        if (inFd == STDIN_FILENO) {
            len = unix_read(inFd, buf, BUFSIZE);
        } else {
            len = adb_read(inFd, buf, BUFSIZE);
        }
        if (len == 0) {
            D("copy_to_file() : read 0 bytes; exiting");
            break;
        }
        if (len < 0) {
            D("copy_to_file(): read failed: %s", strerror(errno));
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

    stdinout_raw_epilogue(inFd, outFd, old_stdin_mode, old_stdout_mode);

    D("copy_to_file() finished after %lu bytes", total);
    free(buf);
}

static void send_window_size_change(int fd, std::unique_ptr<ShellProtocol>& shell) {
    // Old devices can't handle window size changes.
    if (shell == nullptr) return;

#if defined(_WIN32)
    struct winsize {
        unsigned short ws_row;
        unsigned short ws_col;
        unsigned short ws_xpixel;
        unsigned short ws_ypixel;
    };
#endif

    winsize ws;

#if defined(_WIN32)
    // If stdout is redirected to a non-console, we won't be able to get the
    // console size, but that makes sense.
    const intptr_t intptr_handle = _get_osfhandle(STDOUT_FILENO);
    if (intptr_handle == -1) return;

    const HANDLE handle = reinterpret_cast<const HANDLE>(intptr_handle);

    CONSOLE_SCREEN_BUFFER_INFO info;
    memset(&info, 0, sizeof(info));
    if (!GetConsoleScreenBufferInfo(handle, &info)) return;

    memset(&ws, 0, sizeof(ws));
    // The number of visible rows, excluding offscreen scroll-back rows which are in info.dwSize.Y.
    ws.ws_row = info.srWindow.Bottom - info.srWindow.Top + 1;
    // If the user has disabled "Wrap text output on resize", they can make the screen buffer wider
    // than the window, in which case we should use the width of the buffer.
    ws.ws_col = info.dwSize.X;
#else
    if (ioctl(fd, TIOCGWINSZ, &ws) == -1) return;
#endif

    // Send the new window size as human-readable ASCII for debugging convenience.
    size_t l = snprintf(shell->data(), shell->data_capacity(), "%dx%d,%dx%d",
                        ws.ws_row, ws.ws_col, ws.ws_xpixel, ws.ws_ypixel);
    shell->Write(ShellProtocol::kIdWindowSizeChange, l + 1);
}

// Used to pass multiple values to the stdin read thread.
struct StdinReadArgs {
    int stdin_fd, write_fd;
    bool raw_stdin;
    std::unique_ptr<ShellProtocol> protocol;
    char escape_char;
};

// Loops to read from stdin and push the data to the given FD.
// The argument should be a pointer to a StdinReadArgs object. This function
// will take ownership of the object and delete it when finished.
static void stdin_read_thread_loop(void* x) {
    std::unique_ptr<StdinReadArgs> args(reinterpret_cast<StdinReadArgs*>(x));

#if !defined(_WIN32)
    // Mask SIGTTIN in case we're in a backgrounded process.
    sigset_t sigset;
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGTTIN);
    pthread_sigmask(SIG_BLOCK, &sigset, nullptr);
#endif

#if defined(_WIN32)
    // _get_interesting_input_record_uncached() causes unix_read_interruptible()
    // to return -1 with errno == EINTR if the window size changes.
#else
    // Unblock SIGWINCH for this thread, so our read(2) below will be
    // interrupted if the window size changes.
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGWINCH);
    pthread_sigmask(SIG_UNBLOCK, &mask, nullptr);
#endif

    // Set up the initial window size.
    send_window_size_change(args->stdin_fd, args->protocol);

    char raw_buffer[BUFSIZ];
    char* buffer_ptr = raw_buffer;
    size_t buffer_size = sizeof(raw_buffer);
    if (args->protocol != nullptr) {
        buffer_ptr = args->protocol->data();
        buffer_size = args->protocol->data_capacity();
    }

    // If we need to parse escape sequences, make life easy.
    if (args->raw_stdin && args->escape_char != '\0') {
        buffer_size = 1;
    }

    enum EscapeState { kMidFlow, kStartOfLine, kInEscape };
    EscapeState state = kStartOfLine;

    while (true) {
        // Use unix_read_interruptible() rather than adb_read() for stdin.
        D("stdin_read_thread_loop(): pre unix_read_interruptible(fdi=%d,...)", args->stdin_fd);
        int r = unix_read_interruptible(args->stdin_fd, buffer_ptr,
                                        buffer_size);
        if (r == -1 && errno == EINTR) {
            send_window_size_change(args->stdin_fd, args->protocol);
            continue;
        }
        D("stdin_read_thread_loop(): post unix_read_interruptible(fdi=%d,...)", args->stdin_fd);
        if (r <= 0) {
            // Only devices using the shell protocol know to close subprocess
            // stdin. For older devices we want to just leave the connection
            // open, otherwise an unpredictable amount of return data could
            // be lost due to the FD closing before all data has been received.
            if (args->protocol) {
                args->protocol->Write(ShellProtocol::kIdCloseStdin, 0);
            }
            break;
        }
        // If we made stdin raw, check input for escape sequences. In
        // this situation signals like Ctrl+C are sent remotely rather than
        // interpreted locally so this provides an emergency out if the remote
        // process starts ignoring the signal. SSH also does this, see the
        // "escape characters" section on the ssh man page for more info.
        if (args->raw_stdin && args->escape_char != '\0') {
            char ch = buffer_ptr[0];
            if (ch == args->escape_char) {
                if (state == kStartOfLine) {
                    state = kInEscape;
                    // Swallow the escape character.
                    continue;
                } else {
                    state = kMidFlow;
                }
            } else {
                if (state == kInEscape) {
                    if (ch == '.') {
                        fprintf(stderr,"\r\n[ disconnected ]\r\n");
                        stdin_raw_restore();
                        exit(0);
                    } else {
                        // We swallowed an escape character that wasn't part of
                        // a valid escape sequence; time to cough it up.
                        buffer_ptr[0] = args->escape_char;
                        buffer_ptr[1] = ch;
                        ++r;
                    }
                }
                state = (ch == '\n' || ch == '\r') ? kStartOfLine : kMidFlow;
            }
        }
        if (args->protocol) {
            if (!args->protocol->Write(ShellProtocol::kIdStdin, r)) {
                break;
            }
        } else {
            if (!WriteFdExactly(args->write_fd, buffer_ptr, r)) {
                break;
            }
        }
    }
}

// Returns a shell service string with the indicated arguments and command.
static std::string ShellServiceString(bool use_shell_protocol,
                                      const std::string& type_arg,
                                      const std::string& command) {
    std::vector<std::string> args;
    if (use_shell_protocol) {
        args.push_back(kShellServiceArgShellProtocol);

        const char* terminal_type = getenv("TERM");
        if (terminal_type != nullptr) {
            args.push_back(std::string("TERM=") + terminal_type);
        }
    }
    if (!type_arg.empty()) {
        args.push_back(type_arg);
    }

    // Shell service string can look like: shell[,arg1,arg2,...]:[command].
    return android::base::StringPrintf("shell%s%s:%s",
                                       args.empty() ? "" : ",",
                                       android::base::Join(args, ',').c_str(),
                                       command.c_str());
}

// Connects to a shell on the device and read/writes data.
//
// Note: currently this function doesn't properly clean up resources; the
// FD connected to the adb server is never closed and the stdin read thread
// may never exit.
//
// On success returns the remote exit code if |use_shell_protocol| is true,
// 0 otherwise. On failure returns 1.
static int RemoteShell(bool use_shell_protocol, const std::string& type_arg,
                       char escape_char,
                       const std::string& command) {
    std::string service_string = ShellServiceString(use_shell_protocol,
                                                    type_arg, command);

    // Old devices can't handle a service string that's longer than MAX_PAYLOAD_V1.
    // Use |use_shell_protocol| to determine whether to allow a command longer than that.
    if (service_string.size() > MAX_PAYLOAD_V1 && !use_shell_protocol) {
        fprintf(stderr, "error: shell command too long\n");
        return 1;
    }

    // Make local stdin raw if the device allocates a PTY, which happens if:
    //   1. We are explicitly asking for a PTY shell, or
    //   2. We don't specify shell type and are starting an interactive session.
    bool raw_stdin = (type_arg == kShellServiceArgPty ||
                      (type_arg.empty() && command.empty()));

    std::string error;
    int fd = adb_connect(service_string, &error);
    if (fd < 0) {
        fprintf(stderr,"error: %s\n", error.c_str());
        return 1;
    }

    StdinReadArgs* args = new StdinReadArgs;
    if (!args) {
        LOG(ERROR) << "couldn't allocate StdinReadArgs object";
        return 1;
    }
    args->stdin_fd = STDIN_FILENO;
    args->write_fd = fd;
    args->raw_stdin = raw_stdin;
    args->escape_char = escape_char;
    if (use_shell_protocol) {
        args->protocol.reset(new ShellProtocol(args->write_fd));
    }

    if (raw_stdin) stdin_raw_init();

#if !defined(_WIN32)
    // Ensure our process is notified if the local window size changes.
    // We use sigaction(2) to ensure that the SA_RESTART flag is not set,
    // because the whole reason we're sending signals is to unblock the read(2)!
    // That also means we don't need to do anything in the signal handler:
    // the side effect of delivering the signal is all we need.
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = [](int) {};
    sa.sa_flags = 0;
    sigaction(SIGWINCH, &sa, nullptr);

    // Now block SIGWINCH in this thread (the main thread) and all threads spawned
    // from it. The stdin read thread will unblock this signal to ensure that it's
    // the thread that receives the signal.
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGWINCH);
    pthread_sigmask(SIG_BLOCK, &mask, nullptr);
#endif

    // TODO: combine read_and_dump with stdin_read_thread to make life simpler?
    std::thread(stdin_read_thread_loop, args).detach();
    int exit_code = read_and_dump(fd, use_shell_protocol);

    // TODO: properly exit stdin_read_thread_loop and close |fd|.

    // TODO: we should probably install signal handlers for this.
    // TODO: can we use atexit? even on Windows?
    if (raw_stdin) stdin_raw_restore();

    return exit_code;
}

static int adb_shell(int argc, const char** argv) {
    FeatureSet features;
    std::string error;
    if (!adb_get_feature_set(&features, &error)) {
        fprintf(stderr, "error: %s\n", error.c_str());
        return 1;
    }

    enum PtyAllocationMode { kPtyAuto, kPtyNo, kPtyYes, kPtyDefinitely };

    // Defaults.
    char escape_char = '~'; // -e
    bool use_shell_protocol = CanUseFeature(features, kFeatureShell2); // -x
    PtyAllocationMode tty = use_shell_protocol ? kPtyAuto : kPtyDefinitely; // -t/-T

    // Parse shell-specific command-line options.
    argv[0] = "adb shell"; // So getopt(3) error messages start "adb shell".
#ifdef _WIN32
    // fixes "adb shell -l" crash on Windows, b/37284906
    __argv = const_cast<char**>(argv);
#endif
    optind = 1; // argv[0] is always "shell", so set `optind` appropriately.
    int opt;
    while ((opt = getopt(argc, const_cast<char**>(argv), "+e:ntTx")) != -1) {
        switch (opt) {
            case 'e':
                if (!(strlen(optarg) == 1 || strcmp(optarg, "none") == 0)) {
                    return syntax_error("-e requires a single-character argument or 'none'");
                }
                escape_char = (strcmp(optarg, "none") == 0) ? 0 : optarg[0];
                break;
            case 'n':
                close_stdin();
                break;
            case 'x':
                // This option basically asks for historical behavior, so set options that
                // correspond to the historical defaults. This is slightly weird in that -Tx
                // is fine (because we'll undo the -T) but -xT isn't, but that does seem to
                // be our least worst choice...
                use_shell_protocol = false;
                tty = kPtyDefinitely;
                escape_char = '~';
                break;
            case 't':
                // Like ssh, -t arguments are cumulative so that multiple -t's
                // are needed to force a PTY.
                tty = (tty >= kPtyYes) ? kPtyDefinitely : kPtyYes;
                break;
            case 'T':
                tty = kPtyNo;
                break;
            default:
                // getopt(3) already printed an error message for us.
                return 1;
        }
    }

    bool is_interactive = (optind == argc);

    std::string shell_type_arg = kShellServiceArgPty;
    if (tty == kPtyNo) {
        shell_type_arg = kShellServiceArgRaw;
    } else if (tty == kPtyAuto) {
        // If stdin isn't a TTY, default to a raw shell; this lets
        // things like `adb shell < my_script.sh` work as expected.
        // Non-interactive shells should also not have a pty.
        if (!unix_isatty(STDIN_FILENO) || !is_interactive) {
            shell_type_arg = kShellServiceArgRaw;
        }
    } else if (tty == kPtyYes) {
        // A single -t arg isn't enough to override implicit -T.
        if (!unix_isatty(STDIN_FILENO)) {
            fprintf(stderr,
                    "Remote PTY will not be allocated because stdin is not a terminal.\n"
                    "Use multiple -t options to force remote PTY allocation.\n");
            shell_type_arg = kShellServiceArgRaw;
        }
    }

    D("shell -e 0x%x t=%d use_shell_protocol=%s shell_type_arg=%s\n",
      escape_char, tty,
      use_shell_protocol ? "true" : "false",
      (shell_type_arg == kShellServiceArgPty) ? "pty" : "raw");

    // Raw mode is only supported when talking to a new device *and* using the shell protocol.
    if (!use_shell_protocol) {
        if (shell_type_arg != kShellServiceArgPty) {
            fprintf(stderr, "error: %s only supports allocating a pty\n",
                    !CanUseFeature(features, kFeatureShell2) ? "device" : "-x");
            return 1;
        } else {
            // If we're not using the shell protocol, the type argument must be empty.
            shell_type_arg = "";
        }
    }

    std::string command;
    if (optind < argc) {
        // We don't escape here, just like ssh(1). http://b/20564385.
        command = android::base::Join(std::vector<const char*>(argv + optind, argv + argc), ' ');
    }

    return RemoteShell(use_shell_protocol, shell_type_arg, escape_char, command);
}

static int adb_sideload_legacy(const char* filename, int in_fd, int size) {
    std::string error;
    int out_fd = adb_connect(android::base::StringPrintf("sideload:%d", size), &error);
    if (out_fd < 0) {
        fprintf(stderr, "adb: pre-KitKat sideload connection failed: %s\n", error.c_str());
        return -1;
    }

    int opt = CHUNK_SIZE;
    opt = adb_setsockopt(out_fd, SOL_SOCKET, SO_SNDBUF, &opt, sizeof(opt));

    char buf[CHUNK_SIZE];
    int total = size;
    while (size > 0) {
        unsigned xfer = (size > CHUNK_SIZE) ? CHUNK_SIZE : size;
        if (!ReadFdExactly(in_fd, buf, xfer)) {
            fprintf(stderr, "adb: failed to read data from %s: %s\n", filename, strerror(errno));
            adb_close(out_fd);
            return -1;
        }
        if (!WriteFdExactly(out_fd, buf, xfer)) {
            std::string error;
            adb_status(out_fd, &error);
            fprintf(stderr, "adb: failed to write data: %s\n", error.c_str());
            adb_close(out_fd);
            return -1;
        }
        size -= xfer;
        printf("sending: '%s' %4d%%    \r", filename, (int)(100LL - ((100LL * size) / (total))));
        fflush(stdout);
    }
    printf("\n");

    if (!adb_status(out_fd, &error)) {
        fprintf(stderr, "adb: error response: %s\n", error.c_str());
        adb_close(out_fd);
        return -1;
    }

    adb_close(out_fd);
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
static int adb_sideload_host(const char* filename) {
    // TODO: use a LinePrinter instead...
    struct stat sb;
    if (stat(filename, &sb) == -1) {
        fprintf(stderr, "adb: failed to stat file %s: %s\n", filename, strerror(errno));
        return -1;
    }
    unique_fd package_fd(adb_open(filename, O_RDONLY));
    if (package_fd == -1) {
        fprintf(stderr, "adb: failed to open file %s: %s\n", filename, strerror(errno));
        return -1;
    }

    std::string service = android::base::StringPrintf(
        "sideload-host:%d:%d", static_cast<int>(sb.st_size), SIDELOAD_HOST_BLOCK_SIZE);
    std::string error;
    unique_fd device_fd(adb_connect(service, &error));
    if (device_fd < 0) {
        // Try falling back to the older (<= K) sideload method. Maybe this
        // is an older device that doesn't support sideload-host.
        fprintf(stderr, "adb: sideload connection failed: %s\n", error.c_str());
        fprintf(stderr, "adb: trying pre-KitKat sideload method...\n");
        return adb_sideload_legacy(filename, package_fd, static_cast<int>(sb.st_size));
    }

    int opt = SIDELOAD_HOST_BLOCK_SIZE;
    adb_setsockopt(device_fd, SOL_SOCKET, SO_SNDBUF, &opt, sizeof(opt));

    char buf[SIDELOAD_HOST_BLOCK_SIZE];

    size_t xfer = 0;
    int last_percent = -1;
    while (true) {
        if (!ReadFdExactly(device_fd, buf, 8)) {
            fprintf(stderr, "adb: failed to read command: %s\n", strerror(errno));
            return -1;
        }
        buf[8] = '\0';

        if (strcmp("DONEDONE", buf) == 0) {
            printf("\rTotal xfer: %.2fx%*s\n",
                   static_cast<double>(xfer) / (sb.st_size ? sb.st_size : 1),
                   static_cast<int>(strlen(filename) + 10), "");
            return 0;
        }

        int block = strtol(buf, NULL, 10);

        size_t offset = block * SIDELOAD_HOST_BLOCK_SIZE;
        if (offset >= static_cast<size_t>(sb.st_size)) {
            fprintf(stderr, "adb: failed to read block %d past end\n", block);
            return -1;
        }

        size_t to_write = SIDELOAD_HOST_BLOCK_SIZE;
        if ((offset + SIDELOAD_HOST_BLOCK_SIZE) > static_cast<size_t>(sb.st_size)) {
            to_write = sb.st_size - offset;
        }

        if (adb_lseek(package_fd, offset, SEEK_SET) != static_cast<int>(offset)) {
            fprintf(stderr, "adb: failed to seek to package block: %s\n", strerror(errno));
            return -1;
        }
        if (!ReadFdExactly(package_fd, buf, to_write)) {
            fprintf(stderr, "adb: failed to read package block: %s\n", strerror(errno));
            return -1;
        }

        if (!WriteFdExactly(device_fd, buf, to_write)) {
            adb_status(device_fd, &error);
            fprintf(stderr, "adb: failed to write data '%s' *\n", error.c_str());
            return -1;
        }
        xfer += to_write;

        // For normal OTA packages, we expect to transfer every byte
        // twice, plus a bit of overhead (one read during
        // verification, one read of each byte for installation, plus
        // extra access to things like the zip central directory).
        // This estimate of the completion becomes 100% when we've
        // transferred ~2.13 (=100/47) times the package size.
        int percent = static_cast<int>(xfer * 47LL / (sb.st_size ? sb.st_size : 1));
        if (percent != last_percent) {
            printf("\rserving: '%s'  (~%d%%)    ", filename, percent);
            fflush(stdout);
            last_percent = percent;
        }
    }
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
    if (argc < 2) return syntax_error("adb %s <adb service name> [ppp opts]", argv[0]);

    const char* adb_service_name = argv[1];
    std::string error;
    int fd = adb_connect(adb_service_name, &error);
    if (fd < 0) {
        fprintf(stderr, "adb: could not open adb service %s: %s\n", adb_service_name, error.c_str());
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

static bool wait_for_device(const char* service) {
    std::vector<std::string> components = android::base::Split(service, "-");
    if (components.size() < 3 || components.size() > 4) {
        fprintf(stderr, "adb: couldn't parse 'wait-for' command: %s\n", service);
        return false;
    }

    TransportType t;
    adb_get_transport(&t, nullptr, nullptr);

    // Was the caller vague about what they'd like us to wait for?
    // If so, check they weren't more specific in their choice of transport type.
    if (components.size() == 3) {
        auto it = components.begin() + 2;
        if (t == kTransportUsb) {
            components.insert(it, "usb");
        } else if (t == kTransportLocal) {
            components.insert(it, "local");
        } else {
            components.insert(it, "any");
        }
    } else if (components[2] != "any" && components[2] != "local" && components[2] != "usb") {
        fprintf(stderr, "adb: unknown type %s; expected 'any', 'local', or 'usb'\n",
                components[2].c_str());
        return false;
    }

    if (components[3] != "any" && components[3] != "bootloader" && components[3] != "device" &&
        components[3] != "recovery" && components[3] != "sideload") {
        fprintf(stderr,
                "adb: unknown state %s; "
                "expected 'any', 'bootloader', 'device', 'recovery', or 'sideload'\n",
                components[3].c_str());
        return false;
    }

    std::string cmd = format_host_command(android::base::Join(components, "-").c_str());
    return adb_command(cmd);
}

static bool adb_root(const char* command) {
    std::string error;

    unique_fd fd(adb_connect(android::base::StringPrintf("%s:", command), &error));
    if (fd < 0) {
        fprintf(stderr, "adb: unable to connect for %s: %s\n", command, error.c_str());
        return false;
    }

    // Figure out whether we actually did anything.
    char buf[256];
    char* cur = buf;
    ssize_t bytes_left = sizeof(buf);
    while (bytes_left > 0) {
        ssize_t bytes_read = adb_read(fd, cur, bytes_left);
        if (bytes_read == 0) {
            break;
        } else if (bytes_read < 0) {
            fprintf(stderr, "adb: error while reading for %s: %s\n", command, strerror(errno));
            return false;
        }
        cur += bytes_read;
        bytes_left -= bytes_read;
    }

    if (bytes_left == 0) {
        fprintf(stderr, "adb: unexpected output length for %s\n", command);
        return false;
    }

    fflush(stdout);
    WriteFdExactly(STDOUT_FILENO, buf, sizeof(buf) - bytes_left);
    if (cur != buf && strstr(buf, "restarting") == nullptr) {
        return true;
    }

    // Give adbd some time to kill itself and come back up.
    // We can't use wait-for-device because devices (e.g. adb over network) might not come back.
    std::this_thread::sleep_for(3s);
    return true;
}

int send_shell_command(const std::string& command, bool disable_shell_protocol,
                       StandardStreamsCallbackInterface* callback) {
    int fd;
    bool use_shell_protocol = false;

    while (true) {
        bool attempt_connection = true;

        // Use shell protocol if it's supported and the caller doesn't explicitly
        // disable it.
        if (!disable_shell_protocol) {
            FeatureSet features;
            std::string error;
            if (adb_get_feature_set(&features, &error)) {
                use_shell_protocol = CanUseFeature(features, kFeatureShell2);
            } else {
                // Device was unreachable.
                attempt_connection = false;
            }
        }

        if (attempt_connection) {
            std::string error;
            std::string service_string = ShellServiceString(use_shell_protocol, "", command);

            fd = adb_connect(service_string, &error);
            if (fd >= 0) {
                break;
            }
        }

        fprintf(stderr, "- waiting for device -\n");
        if (!wait_for_device("wait-for-device")) {
            return 1;
        }
    }

    int exit_code = read_and_dump(fd, use_shell_protocol, callback);

    if (adb_close(fd) < 0) {
        PLOG(ERROR) << "failure closing FD " << fd;
    }

    return exit_code;
}

static int logcat(int argc, const char** argv) {
    char* log_tags = getenv("ANDROID_LOG_TAGS");
    std::string quoted = escape_arg(log_tags == nullptr ? "" : log_tags);

    std::string cmd = "export ANDROID_LOG_TAGS=\"" + quoted + "\"; exec logcat";

    if (!strcmp(argv[0], "longcat")) {
        cmd += " -v long";
    }

    --argc;
    ++argv;
    while (argc-- > 0) {
        cmd += " " + escape_arg(*argv++);
    }

    // No need for shell protocol with logcat, always disable for simplicity.
    return send_shell_command(cmd, true);
}

static void write_zeros(int bytes, int fd) {
    int old_stdin_mode = -1;
    int old_stdout_mode = -1;
    char* buf = (char*) calloc(1, bytes);
    if (buf == nullptr) fatal("couldn't allocate buffer for write_zeros");

    D("write_zeros(%d) -> %d", bytes, fd);

    stdinout_raw_prologue(-1, fd, old_stdin_mode, old_stdout_mode);

    if (fd == STDOUT_FILENO) {
        fwrite(buf, 1, bytes, stdout);
        fflush(stdout);
    } else {
        adb_write(fd, buf, bytes);
    }

    stdinout_raw_prologue(-1, fd, old_stdin_mode, old_stdout_mode);

    D("write_zeros() finished");
    free(buf);
}

static int backup(int argc, const char** argv) {
    const char* filename = "backup.ab";

    /* find, extract, and use any -f argument */
    for (int i = 1; i < argc; i++) {
        if (!strcmp("-f", argv[i])) {
            if (i == argc - 1) return syntax_error("backup -f passed with no filename");
            filename = argv[i+1];
            for (int j = i+2; j <= argc; ) {
                argv[i++] = argv[j++];
            }
            argc -= 2;
            argv[argc] = NULL;
        }
    }

    // Bare "adb backup" or "adb backup -f filename" are not valid invocations ---
    // a list of packages is required.
    if (argc < 2) return syntax_error("backup either needs a list of packages or -all/-shared");

    adb_unlink(filename);
    int outFd = adb_creat(filename, 0640);
    if (outFd < 0) {
        fprintf(stderr, "adb: backup unable to create file '%s': %s\n", filename, strerror(errno));
        return EXIT_FAILURE;
    }

    std::string cmd = "backup:";
    --argc;
    ++argv;
    while (argc-- > 0) {
        cmd += " " + escape_arg(*argv++);
    }

    D("backup. filename=%s cmd=%s", filename, cmd.c_str());
    std::string error;
    int fd = adb_connect(cmd, &error);
    if (fd < 0) {
        fprintf(stderr, "adb: unable to connect for backup: %s\n", error.c_str());
        adb_close(outFd);
        return EXIT_FAILURE;
    }

    fprintf(stdout, "Now unlock your device and confirm the backup operation...\n");
    fflush(stdout);

    copy_to_file(fd, outFd);

    adb_close(fd);
    adb_close(outFd);
    return EXIT_SUCCESS;
}

static int restore(int argc, const char** argv) {
    if (argc != 2) return syntax_error("restore requires an argument");

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

    fprintf(stdout, "Now unlock your device and confirm the restore operation.\n");
    fflush(stdout);

    copy_to_file(tarFd, fd);

    // Provide an in-band EOD marker in case the archive file is malformed
    write_zeros(512*2, fd);

    // Wait until the other side finishes, or it'll get sent SIGHUP.
    copy_to_file(fd, STDOUT_FILENO);

    adb_close(fd);
    adb_close(tarFd);
    return 0;
}

static void parse_push_pull_args(const char** arg, int narg, std::vector<const char*>* srcs,
                                 const char** dst, bool* copy_attrs, bool* sync) {
    *copy_attrs = false;

    srcs->clear();
    bool ignore_flags = false;
    while (narg > 0) {
        if (ignore_flags || *arg[0] != '-') {
            srcs->push_back(*arg);
        } else {
            if (!strcmp(*arg, "-p")) {
                // Silently ignore for backwards compatibility.
            } else if (!strcmp(*arg, "-a")) {
                *copy_attrs = true;
            } else if (!strcmp(*arg, "--sync")) {
                if (sync != nullptr) {
                    *sync = true;
                }
            } else if (!strcmp(*arg, "--")) {
                ignore_flags = true;
            } else {
                syntax_error("unrecognized option '%s'", *arg);
                exit(1);
            }
        }
        ++arg;
        --narg;
    }

    if (srcs->size() > 1) {
        *dst = srcs->back();
        srcs->pop_back();
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

// Disallow stdin, stdout, and stderr.
static bool _is_valid_ack_reply_fd(const int ack_reply_fd) {
#ifdef _WIN32
    const HANDLE ack_reply_handle = cast_int_to_handle(ack_reply_fd);
    return (GetStdHandle(STD_INPUT_HANDLE) != ack_reply_handle) &&
           (GetStdHandle(STD_OUTPUT_HANDLE) != ack_reply_handle) &&
           (GetStdHandle(STD_ERROR_HANDLE) != ack_reply_handle);
#else
    return ack_reply_fd > 2;
#endif
}

static bool _use_legacy_install() {
    FeatureSet features;
    std::string error;
    if (!adb_get_feature_set(&features, &error)) {
        fprintf(stderr, "error: %s\n", error.c_str());
        return true;
    }
    return !CanUseFeature(features, kFeatureCmd);
}

int adb_commandline(int argc, const char** argv) {
    int no_daemon = 0;
    int is_daemon = 0;
    int is_server = 0;
    int r;
    TransportType transport_type = kTransportAny;
    int ack_reply_fd = -1;

#if !defined(_WIN32)
    // We'd rather have EPIPE than SIGPIPE.
    signal(SIGPIPE, SIG_IGN);
#endif

    const char* server_host_str = nullptr;
    const char* server_port_str = nullptr;
    const char* server_socket_str = nullptr;

    // We need to check for -d and -e before we look at $ANDROID_SERIAL.
    const char* serial = nullptr;
    TransportId transport_id = 0;

    while (argc > 0) {
        if (!strcmp(argv[0],"server")) {
            is_server = 1;
        } else if (!strcmp(argv[0],"nodaemon")) {
            no_daemon = 1;
        } else if (!strcmp(argv[0], "fork-server")) {
            /* this is a special flag used only when the ADB client launches the ADB Server */
            is_daemon = 1;
        } else if (!strcmp(argv[0], "--reply-fd")) {
            if (argc < 2) return syntax_error("--reply-fd requires an argument");
            const char* reply_fd_str = argv[1];
            argc--;
            argv++;
            ack_reply_fd = strtol(reply_fd_str, nullptr, 10);
            if (!_is_valid_ack_reply_fd(ack_reply_fd)) {
                fprintf(stderr, "adb: invalid reply fd \"%s\"\n", reply_fd_str);
                return 1;
            }
        } else if (!strncmp(argv[0], "-s", 2)) {
            if (isdigit(argv[0][2])) {
                serial = argv[0] + 2;
            } else {
                if (argc < 2 || argv[0][2] != '\0') return syntax_error("-s requires an argument");
                serial = argv[1];
                argc--;
                argv++;
            }
        } else if (!strncmp(argv[0], "-t", 2)) {
            const char* id;
            if (isdigit(argv[0][2])) {
                id = argv[0] + 2;
            } else {
                id = argv[1];
                argc--;
                argv++;
            }
            transport_id = strtoll(id, const_cast<char**>(&id), 10);
            if (*id != '\0') {
                return syntax_error("invalid transport id");
            }
        } else if (!strcmp(argv[0],"-d")) {
            transport_type = kTransportUsb;
        } else if (!strcmp(argv[0],"-e")) {
            transport_type = kTransportLocal;
        } else if (!strcmp(argv[0],"-a")) {
            gListenAll = 1;
        } else if (!strncmp(argv[0], "-H", 2)) {
            if (argv[0][2] == '\0') {
                if (argc < 2) return syntax_error("-H requires an argument");
                server_host_str = argv[1];
                argc--;
                argv++;
            } else {
                server_host_str = argv[0] + 2;
            }
        } else if (!strncmp(argv[0], "-P", 2)) {
            if (argv[0][2] == '\0') {
                if (argc < 2) return syntax_error("-P requires an argument");
                server_port_str = argv[1];
                argc--;
                argv++;
            } else {
                server_port_str = argv[0] + 2;
            }
        } else if (!strcmp(argv[0], "-L")) {
            if (argc < 2) return syntax_error("-L requires an argument");
            server_socket_str = argv[1];
            argc--;
            argv++;
        } else {
            /* out of recognized modifiers and flags */
            break;
        }
        argc--;
        argv++;
    }

    if ((server_host_str || server_port_str) && server_socket_str) {
        return syntax_error("-L is incompatible with -H or -P");
    }

    // If -L, -H, or -P are specified, ignore environment variables.
    // Otherwise, prefer ADB_SERVER_SOCKET over ANDROID_ADB_SERVER_ADDRESS/PORT.
    if (!server_host_str && !server_port_str && !server_socket_str) {
        server_socket_str = getenv("ADB_SERVER_SOCKET");
    }

    if (!server_socket_str) {
        // tcp:1234 and tcp:localhost:1234 are different with -a, so don't default to localhost
        server_host_str = server_host_str ? server_host_str : getenv("ANDROID_ADB_SERVER_ADDRESS");

        int server_port = DEFAULT_ADB_PORT;
        server_port_str = server_port_str ? server_port_str : getenv("ANDROID_ADB_SERVER_PORT");
        if (server_port_str && strlen(server_port_str) > 0) {
            if (!android::base::ParseInt(server_port_str, &server_port, 1, 65535)) {
                fprintf(stderr,
                        "adb: Env var ANDROID_ADB_SERVER_PORT must be a positive"
                        " number less than 65535. Got \"%s\"\n",
                        server_port_str);
                exit(1);
            }
        }

        int rc;
        char* temp;
        if (server_host_str) {
            rc = asprintf(&temp, "tcp:%s:%d", server_host_str, server_port);
        } else {
            rc = asprintf(&temp, "tcp:%d", server_port);
        }
        if (rc < 0) {
            fatal("failed to allocate server socket specification");
        }
        server_socket_str = temp;
    }

    adb_set_socket_spec(server_socket_str);

    // If none of -d, -e, or -s were specified, try $ANDROID_SERIAL.
    if (transport_type == kTransportAny && serial == nullptr) {
        serial = getenv("ANDROID_SERIAL");
    }

    adb_set_transport(transport_type, serial, transport_id);

    if (is_server) {
        if (no_daemon || is_daemon) {
            if (is_daemon && (ack_reply_fd == -1)) {
                fprintf(stderr, "reply fd for adb server to client communication not specified.\n");
                return 1;
            }
            r = adb_server_main(is_daemon, server_socket_str, ack_reply_fd);
        } else {
            r = launch_server(server_socket_str);
        }
        if (r) {
            fprintf(stderr,"* could not start server *\n");
        }
        return r;
    }

    if (argc == 0) {
        help();
        return 1;
    }

    /* handle wait-for-* prefix */
    if (!strncmp(argv[0], "wait-for-", strlen("wait-for-"))) {
        const char* service = argv[0];

        if (!wait_for_device(service)) {
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
            return syntax_error("adb devices [-l]");
        }

        std::string query = android::base::StringPrintf("host:%s%s", argv[0], listopt);
        printf("List of devices attached\n");
        return adb_query_command(query);
    }
    else if (!strcmp(argv[0], "connect")) {
        if (argc != 2) return syntax_error("adb connect <host>[:<port>]");

        std::string query = android::base::StringPrintf("host:connect:%s", argv[1]);
        return adb_query_command(query);
    }
    else if (!strcmp(argv[0], "disconnect")) {
        if (argc > 2) return syntax_error("adb disconnect [<host>[:<port>]]");

        std::string query = android::base::StringPrintf("host:disconnect:%s",
                                                        (argc == 2) ? argv[1] : "");
        return adb_query_command(query);
    }
    else if (!strcmp(argv[0], "emu")) {
        return adb_send_emulator_command(argc, argv, serial);
    }
    else if (!strcmp(argv[0], "shell")) {
        return adb_shell(argc, argv);
    }
    else if (!strcmp(argv[0], "exec-in") || !strcmp(argv[0], "exec-out")) {
        int exec_in = !strcmp(argv[0], "exec-in");

        if (argc < 2) return syntax_error("adb %s command", argv[0]);

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
        return adb_kill_server() ? 0 : 1;
    }
    else if (!strcmp(argv[0], "sideload")) {
        if (argc != 2) return syntax_error("sideload requires an argument");
        if (adb_sideload_host(argv[1])) {
            return 1;
        } else {
            return 0;
        }
    } else if (!strcmp(argv[0], "tcpip")) {
        if (argc != 2) return syntax_error("tcpip requires an argument");
        int port;
        if (!android::base::ParseInt(argv[1], &port, 1, 65535)) {
            return syntax_error("tcpip: invalid port: %s", argv[1]);
        }
        return adb_connect_command(android::base::StringPrintf("tcpip:%d", port));
    }
    else if (!strcmp(argv[0], "remount") ||
             !strcmp(argv[0], "reboot") ||
             !strcmp(argv[0], "reboot-bootloader") ||
             !strcmp(argv[0], "usb") ||
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
    } else if (!strcmp(argv[0], "root") || !strcmp(argv[0], "unroot")) {
        return adb_root(argv[0]) ? 0 : 1;
    } else if (!strcmp(argv[0], "bugreport")) {
        Bugreport bugreport;
        return bugreport.DoIt(argc, argv);
    } else if (!strcmp(argv[0], "forward") || !strcmp(argv[0], "reverse")) {
        bool reverse = !strcmp(argv[0], "reverse");
        ++argv;
        --argc;
        if (argc < 1) return syntax_error("%s requires an argument", argv[0]);

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

        std::string cmd, error;
        if (strcmp(argv[0], "--list") == 0) {
            if (argc != 1) return syntax_error("--list doesn't take any arguments");
            return adb_query_command(host_prefix + ":list-forward");
        } else if (strcmp(argv[0], "--remove-all") == 0) {
            if (argc != 1) return syntax_error("--remove-all doesn't take any arguments");
            cmd = host_prefix + ":killforward-all";
        } else if (strcmp(argv[0], "--remove") == 0) {
            // forward --remove <local>
            if (argc != 2) return syntax_error("--remove requires an argument");
            cmd = host_prefix + ":killforward:" + argv[1];
        } else if (strcmp(argv[0], "--no-rebind") == 0) {
            // forward --no-rebind <local> <remote>
            if (argc != 3) return syntax_error("--no-rebind takes two arguments");
            if (forward_targets_are_valid(argv[1], argv[2], &error)) {
                cmd = host_prefix + ":forward:norebind:" + argv[1] + ";" + argv[2];
            }
        } else {
            // forward <local> <remote>
            if (argc != 2) return syntax_error("forward takes two arguments");
            if (forward_targets_are_valid(argv[0], argv[1], &error)) {
                cmd = host_prefix + ":forward:" + argv[0] + ";" + argv[1];
            }
        }

        if (!error.empty()) {
            fprintf(stderr, "error: %s\n", error.c_str());
            return 1;
        }

        int fd = adb_connect(cmd, &error);
        if (fd < 0 || !adb_status(fd, &error)) {
            adb_close(fd);
            fprintf(stderr, "error: %s\n", error.c_str());
            return 1;
        }

        // Server or device may optionally return a resolved TCP port number.
        std::string resolved_port;
        if (ReadProtocolString(fd, &resolved_port, &error) && !resolved_port.empty()) {
            printf("%s\n", resolved_port.c_str());
        }

        ReadOrderlyShutdown(fd);
        return 0;
    }
    /* do_sync_*() commands */
    else if (!strcmp(argv[0], "ls")) {
        if (argc != 2) return syntax_error("ls requires an argument");
        return do_sync_ls(argv[1]) ? 0 : 1;
    }
    else if (!strcmp(argv[0], "push")) {
        bool copy_attrs = false;
        bool sync = false;
        std::vector<const char*> srcs;
        const char* dst = nullptr;

        parse_push_pull_args(&argv[1], argc - 1, &srcs, &dst, &copy_attrs, &sync);
        if (srcs.empty() || !dst) return syntax_error("push requires an argument");
        return do_sync_push(srcs, dst, sync) ? 0 : 1;
    }
    else if (!strcmp(argv[0], "pull")) {
        bool copy_attrs = false;
        std::vector<const char*> srcs;
        const char* dst = ".";

        parse_push_pull_args(&argv[1], argc - 1, &srcs, &dst, &copy_attrs, nullptr);
        if (srcs.empty()) return syntax_error("pull requires an argument");
        return do_sync_pull(srcs, dst, copy_attrs) ? 0 : 1;
    }
    else if (!strcmp(argv[0], "install")) {
        if (argc < 2) return syntax_error("install requires an argument");
        if (_use_legacy_install()) {
            return install_app_legacy(argc, argv);
        }
        return install_app(argc, argv);
    }
    else if (!strcmp(argv[0], "install-multiple")) {
        if (argc < 2) return syntax_error("install-multiple requires an argument");
        return install_multiple_app(argc, argv);
    }
    else if (!strcmp(argv[0], "uninstall")) {
        if (argc < 2) return syntax_error("uninstall requires an argument");
        if (_use_legacy_install()) {
            return uninstall_app_legacy(argc, argv);
        }
        return uninstall_app(argc, argv);
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
            return syntax_error("adb sync [-l] [PARTITION]");
        }

        if (src == "all") src = "";

        if (src != "" &&
            src != "system" && src != "data" && src != "vendor" && src != "oem") {
            return syntax_error("don't know how to sync %s partition", src.c_str());
        }

        std::string system_src_path = product_file("system");
        std::string data_src_path = product_file("data");
        std::string vendor_src_path = product_file("vendor");
        std::string oem_src_path = product_file("oem");

        bool okay = true;
        if (okay && (src.empty() || src == "system")) {
            okay = do_sync_sync(system_src_path, "/system", list_only);
        }
        if (okay && (src.empty() || src == "vendor") && directory_exists(vendor_src_path)) {
            okay = do_sync_sync(vendor_src_path, "/vendor", list_only);
        }
        if (okay && (src.empty() || src == "oem") && directory_exists(oem_src_path)) {
            okay = do_sync_sync(oem_src_path, "/oem", list_only);
        }
        if (okay && (src.empty() || src == "data")) {
            okay = do_sync_sync(data_src_path, "/data", list_only);
        }
        return okay ? 0 : 1;
    }
    /* passthrough commands */
    else if (!strcmp(argv[0],"get-state") ||
        !strcmp(argv[0],"get-serialno") ||
        !strcmp(argv[0],"get-devpath"))
    {
        return adb_query_command(format_host_command(argv[0]));
    }
    /* other commands */
    else if (!strcmp(argv[0],"logcat") || !strcmp(argv[0],"lolcat") || !strcmp(argv[0],"longcat")) {
        return logcat(argc, argv);
    }
    else if (!strcmp(argv[0],"ppp")) {
        return ppp(argc, argv);
    }
    else if (!strcmp(argv[0], "start-server")) {
        std::string error;
        const int result = adb_connect("host:start-server", &error);
        if (result < 0) {
            fprintf(stderr, "error: %s\n", error.c_str());
        }
        return result;
    }
    else if (!strcmp(argv[0], "backup")) {
        return backup(argc, argv);
    }
    else if (!strcmp(argv[0], "restore")) {
        return restore(argc, argv);
    }
    else if (!strcmp(argv[0], "keygen")) {
        if (argc != 2) return syntax_error("keygen requires an argument");
        // Always print key generation information for keygen command.
        adb_trace_enable(AUTH);
        return adb_auth_keygen(argv[1]);
    }
    else if (!strcmp(argv[0], "jdwp")) {
        return adb_connect_command("jdwp");
    }
    else if (!strcmp(argv[0], "track-jdwp")) {
        return adb_connect_command("track-jdwp");
    }
    else if (!strcmp(argv[0], "track-devices")) {
        return adb_connect_command("host:track-devices");
    }


    /* "adb /?" is a common idiom under Windows */
    else if (!strcmp(argv[0], "--help") || !strcmp(argv[0], "help") || !strcmp(argv[0], "/?")) {
        help();
        return 0;
    }
    else if (!strcmp(argv[0], "--version") || !strcmp(argv[0], "version")) {
        fprintf(stdout, "%s", adb_version().c_str());
        return 0;
    } else if (!strcmp(argv[0], "features")) {
        // Only list the features common to both the adb client and the device.
        FeatureSet features;
        std::string error;
        if (!adb_get_feature_set(&features, &error)) {
            fprintf(stderr, "error: %s\n", error.c_str());
            return 1;
        }

        for (const std::string& name : features) {
            if (CanUseFeature(features, name)) {
                printf("%s\n", name.c_str());
            }
        }
        return 0;
    } else if (!strcmp(argv[0], "host-features")) {
        return adb_query_command("host:host-features");
    } else if (!strcmp(argv[0], "reconnect")) {
        if (argc == 1) {
            return adb_query_command(format_host_command(argv[0]));
        } else if (argc == 2) {
            if (!strcmp(argv[1], "device")) {
                std::string err;
                adb_connect("reconnect", &err);
                return 0;
            } else if (!strcmp(argv[1], "offline")) {
                std::string err;
                return adb_query_command("host:reconnect-offline");
            } else {
                return syntax_error("adb reconnect [device|offline]");
            }
        }
    }

    syntax_error("unknown command %s", argv[0]);
    return 1;
}

static int uninstall_app(int argc, const char** argv) {
    // 'adb uninstall' takes the same arguments as 'cmd package uninstall' on device
    std::string cmd = "cmd package";
    while (argc-- > 0) {
        // deny the '-k' option until the remaining data/cache can be removed with adb/UI
        if (strcmp(*argv, "-k") == 0) {
            printf(
                "The -k option uninstalls the application while retaining the data/cache.\n"
                "At the moment, there is no way to remove the remaining data.\n"
                "You will have to reinstall the application with the same signature, and fully uninstall it.\n"
                "If you truly wish to continue, execute 'adb shell cmd package uninstall -k'.\n");
            return EXIT_FAILURE;
        }
        cmd += " " + escape_arg(*argv++);
    }

    return send_shell_command(cmd, false);
}

static int install_app(int argc, const char** argv) {
    // The last argument must be the APK file
    const char* file = argv[argc - 1];
    if (!android::base::EndsWithIgnoreCase(file, ".apk")) {
        return syntax_error("filename doesn't end .apk: %s", file);
    }

    struct stat sb;
    if (stat(file, &sb) == -1) {
        fprintf(stderr, "adb: failed to stat %s: %s\n", file, strerror(errno));
        return 1;
    }

    int localFd = adb_open(file, O_RDONLY);
    if (localFd < 0) {
        fprintf(stderr, "adb: failed to open %s: %s\n", file, strerror(errno));
        return 1;
    }

    std::string error;
    std::string cmd = "exec:cmd package";

    // don't copy the APK name, but, copy the rest of the arguments as-is
    while (argc-- > 1) {
        cmd += " " + escape_arg(std::string(*argv++));
    }

    // add size parameter [required for streaming installs]
    // do last to override any user specified value
    cmd += " " + android::base::StringPrintf("-S %" PRIu64, static_cast<uint64_t>(sb.st_size));

    int remoteFd = adb_connect(cmd, &error);
    if (remoteFd < 0) {
        fprintf(stderr, "adb: connect error for write: %s\n", error.c_str());
        adb_close(localFd);
        return 1;
    }

    char buf[BUFSIZ];
    copy_to_file(localFd, remoteFd);
    read_status_line(remoteFd, buf, sizeof(buf));

    adb_close(localFd);
    adb_close(remoteFd);

    if (!strncmp("Success", buf, 7)) {
        fputs(buf, stdout);
        return 0;
    }
    fprintf(stderr, "adb: failed to install %s: %s", file, buf);
    return 1;
}

static int install_multiple_app(int argc, const char** argv) {
    // Find all APK arguments starting at end.
    // All other arguments passed through verbatim.
    int first_apk = -1;
    uint64_t total_size = 0;
    for (int i = argc - 1; i >= 0; i--) {
        const char* file = argv[i];

        if (android::base::EndsWithIgnoreCase(file, ".apk")) {
            struct stat sb;
            if (stat(file, &sb) != -1) total_size += sb.st_size;
            first_apk = i;
        } else {
            break;
        }
    }

    if (first_apk == -1) return syntax_error("need APK file on command line");

    std::string install_cmd;
    if (_use_legacy_install()) {
        install_cmd = "exec:pm";
    } else {
        install_cmd = "exec:cmd package";
    }

    std::string cmd = android::base::StringPrintf("%s install-create -S %" PRIu64, install_cmd.c_str(), total_size);
    for (int i = 1; i < first_apk; i++) {
        cmd += " " + escape_arg(argv[i]);
    }

    // Create install session
    std::string error;
    int fd = adb_connect(cmd, &error);
    if (fd < 0) {
        fprintf(stderr, "adb: connect error for create: %s\n", error.c_str());
        return EXIT_FAILURE;
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
        fprintf(stderr, "adb: failed to create session\n");
        fputs(buf, stderr);
        return EXIT_FAILURE;
    }

    // Valid session, now stream the APKs
    int success = 1;
    for (int i = first_apk; i < argc; i++) {
        const char* file = argv[i];
        struct stat sb;
        if (stat(file, &sb) == -1) {
            fprintf(stderr, "adb: failed to stat %s: %s\n", file, strerror(errno));
            success = 0;
            goto finalize_session;
        }

        std::string cmd = android::base::StringPrintf(
                "%s install-write -S %" PRIu64 " %d %d_%s -",
                install_cmd.c_str(), static_cast<uint64_t>(sb.st_size), session_id, i,
                android::base::Basename(file).c_str());

        int localFd = adb_open(file, O_RDONLY);
        if (localFd < 0) {
            fprintf(stderr, "adb: failed to open %s: %s\n", file, strerror(errno));
            success = 0;
            goto finalize_session;
        }

        std::string error;
        int remoteFd = adb_connect(cmd, &error);
        if (remoteFd < 0) {
            fprintf(stderr, "adb: connect error for write: %s\n", error.c_str());
            adb_close(localFd);
            success = 0;
            goto finalize_session;
        }

        copy_to_file(localFd, remoteFd);
        read_status_line(remoteFd, buf, sizeof(buf));

        adb_close(localFd);
        adb_close(remoteFd);

        if (strncmp("Success", buf, 7)) {
            fprintf(stderr, "adb: failed to write %s\n", file);
            fputs(buf, stderr);
            success = 0;
            goto finalize_session;
        }
    }

finalize_session:
    // Commit session if we streamed everything okay; otherwise abandon
    std::string service =
            android::base::StringPrintf("%s install-%s %d",
                                        install_cmd.c_str(), success ? "commit" : "abandon", session_id);
    fd = adb_connect(service, &error);
    if (fd < 0) {
        fprintf(stderr, "adb: connect error for finalize: %s\n", error.c_str());
        return EXIT_FAILURE;
    }
    read_status_line(fd, buf, sizeof(buf));
    adb_close(fd);

    if (!strncmp("Success", buf, 7)) {
        fputs(buf, stdout);
        return 0;
    }
    fprintf(stderr, "adb: failed to finalize session\n");
    fputs(buf, stderr);
    return EXIT_FAILURE;
}

static int pm_command(int argc, const char** argv) {
    std::string cmd = "pm";

    while (argc-- > 0) {
        cmd += " " + escape_arg(*argv++);
    }

    return send_shell_command(cmd, false);
}

static int uninstall_app_legacy(int argc, const char** argv) {
    /* if the user choose the -k option, we refuse to do it until devices are
       out with the option to uninstall the remaining data somehow (adb/ui) */
    int i;
    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-k")) {
            printf(
                "The -k option uninstalls the application while retaining the data/cache.\n"
                "At the moment, there is no way to remove the remaining data.\n"
                "You will have to reinstall the application with the same signature, and fully uninstall it.\n"
                "If you truly wish to continue, execute 'adb shell pm uninstall -k'\n.");
            return EXIT_FAILURE;
        }
    }

    /* 'adb uninstall' takes the same arguments as 'pm uninstall' on device */
    return pm_command(argc, argv);
}

static int delete_file(const std::string& filename) {
    std::string cmd = "rm -f " + escape_arg(filename);
    return send_shell_command(cmd, false);
}

static int install_app_legacy(int argc, const char** argv) {
    static const char *const DATA_DEST = "/data/local/tmp/%s";
    static const char *const SD_DEST = "/sdcard/tmp/%s";
    const char* where = DATA_DEST;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-s")) {
            where = SD_DEST;
        }
    }

    // Find last APK argument.
    // All other arguments passed through verbatim.
    int last_apk = -1;
    for (int i = argc - 1; i >= 0; i--) {
        if (android::base::EndsWithIgnoreCase(argv[i], ".apk")) {
            last_apk = i;
            break;
        }
    }

    if (last_apk == -1) return syntax_error("need APK file on command line");

    int result = -1;
    std::vector<const char*> apk_file = {argv[last_apk]};
    std::string apk_dest = android::base::StringPrintf(
        where, android::base::Basename(argv[last_apk]).c_str());
    if (!do_sync_push(apk_file, apk_dest.c_str(), false)) goto cleanup_apk;
    argv[last_apk] = apk_dest.c_str(); /* destination name, not source location */
    result = pm_command(argc, argv);

cleanup_apk:
    delete_file(apk_dest);
    return result;
}

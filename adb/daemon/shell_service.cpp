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

// Functionality for launching and managing shell subprocesses.
//
// There are two types of subprocesses, PTY or raw. PTY is typically used for
// an interactive session, raw for non-interactive. There are also two methods
// of communication with the subprocess, passing raw data or using a simple
// protocol to wrap packets. The protocol allows separating stdout/stderr and
// passing the exit code back, but is not backwards compatible.
//   ----------------+--------------------------------------
//   Type  Protocol  |   Exit code?  Separate stdout/stderr?
//   ----------------+--------------------------------------
//   PTY   No        |   No          No
//   Raw   No        |   No          No
//   PTY   Yes       |   Yes         No
//   Raw   Yes       |   Yes         Yes
//   ----------------+--------------------------------------
//
// Non-protocol subprocesses work by passing subprocess stdin/out/err through
// a single pipe which is registered with a local socket in adbd. The local
// socket uses the fdevent loop to pass raw data between this pipe and the
// transport, which then passes data back to the adb client. Cleanup is done by
// waiting in a separate thread for the subprocesses to exit and then signaling
// a separate fdevent to close out the local socket from the main loop.
//
// ------------------+-------------------------+------------------------------
//   Subprocess      |  adbd subprocess thread |   adbd main fdevent loop
// ------------------+-------------------------+------------------------------
//                   |                         |
//   stdin/out/err <----------------------------->       LocalSocket
//      |            |                         |
//      |            |      Block on exit      |
//      |            |           *             |
//      v            |           *             |
//     Exit         --->      Unblock          |
//                   |           |             |
//                   |           v             |
//                   |   Notify shell exit FD --->    Close LocalSocket
// ------------------+-------------------------+------------------------------
//
// The protocol requires the thread to intercept stdin/out/err in order to
// wrap/unwrap data with shell protocol packets.
//
// ------------------+-------------------------+------------------------------
//   Subprocess      |  adbd subprocess thread |   adbd main fdevent loop
// ------------------+-------------------------+------------------------------
//                   |                         |
//     stdin/out   <--->      Protocol       <--->       LocalSocket
//     stderr       --->      Protocol        --->       LocalSocket
//       |           |                         |
//       v           |                         |
//      Exit        --->  Exit code protocol  --->       LocalSocket
//                   |           |             |
//                   |           v             |
//                   |   Notify shell exit FD --->    Close LocalSocket
// ------------------+-------------------------+------------------------------
//
// An alternate approach is to put the protocol wrapping/unwrapping in the main
// fdevent loop, which has the advantage of being able to re-use the existing
// select() code for handling data streams. However, implementation turned out
// to be more complex due to partial reads and non-blocking I/O so this model
// was chosen instead.

#define TRACE_TAG SHELL

#include "sysdeps.h"

#include "shell_service.h"

#include <errno.h>
#include <paths.h>
#include <pty.h>
#include <pwd.h>
#include <sys/select.h>
#include <termios.h>

#include <memory>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <private/android_logger.h>
#include <selinux/android.h>

#include "adb.h"
#include "adb_io.h"
#include "adb_trace.h"
#include "adb_unique_fd.h"
#include "adb_utils.h"
#include "security_log_tags.h"
#include "shell_protocol.h"

namespace {

// Reads from |fd| until close or failure.
std::string ReadAll(int fd) {
    char buffer[512];
    std::string received;

    while (1) {
        int bytes = adb_read(fd, buffer, sizeof(buffer));
        if (bytes <= 0) {
            break;
        }
        received.append(buffer, bytes);
    }

    return received;
}

// Creates a socketpair and saves the endpoints to |fd1| and |fd2|.
bool CreateSocketpair(unique_fd* fd1, unique_fd* fd2) {
    int sockets[2];
    if (adb_socketpair(sockets) < 0) {
        PLOG(ERROR) << "cannot create socket pair";
        return false;
    }
    fd1->reset(sockets[0]);
    fd2->reset(sockets[1]);
    return true;
}

class Subprocess {
  public:
    Subprocess(const std::string& command, const char* terminal_type,
               SubprocessType type, SubprocessProtocol protocol);
    ~Subprocess();

    const std::string& command() const { return command_; }

    int ReleaseLocalSocket() { return local_socket_sfd_.release(); }

    pid_t pid() const { return pid_; }

    // Sets up FDs, forks a subprocess, starts the subprocess manager thread,
    // and exec's the child. Returns false and sets error on failure.
    bool ForkAndExec(std::string* _Nonnull error);

    // Start the subprocess manager thread. Consumes the subprocess, regardless of success.
    // Returns false and sets error on failure.
    static bool StartThread(std::unique_ptr<Subprocess> subprocess,
                            std::string* _Nonnull error);

  private:
    // Opens the file at |pts_name|.
    int OpenPtyChildFd(const char* pts_name, unique_fd* error_sfd);

    static void ThreadHandler(void* userdata);
    void PassDataStreams();
    void WaitForExit();

    unique_fd* SelectLoop(fd_set* master_read_set_ptr,
                          fd_set* master_write_set_ptr);

    // Input/output stream handlers. Success returns nullptr, failure returns
    // a pointer to the failed FD.
    unique_fd* PassInput();
    unique_fd* PassOutput(unique_fd* sfd, ShellProtocol::Id id);

    const std::string command_;
    const std::string terminal_type_;
    bool make_pty_raw_ = false;
    SubprocessType type_;
    SubprocessProtocol protocol_;
    pid_t pid_ = -1;
    unique_fd local_socket_sfd_;

    // Shell protocol variables.
    unique_fd stdinout_sfd_, stderr_sfd_, protocol_sfd_;
    std::unique_ptr<ShellProtocol> input_, output_;
    size_t input_bytes_left_ = 0;

    DISALLOW_COPY_AND_ASSIGN(Subprocess);
};

Subprocess::Subprocess(const std::string& command, const char* terminal_type,
                       SubprocessType type, SubprocessProtocol protocol)
    : command_(command),
      terminal_type_(terminal_type ? terminal_type : ""),
      type_(type),
      protocol_(protocol) {
    // If we aren't using the shell protocol we must allocate a PTY to properly close the
    // subprocess. PTYs automatically send SIGHUP to the slave-side process when the master side
    // of the PTY closes, which we rely on. If we use a raw pipe, processes that don't read/write,
    // e.g. screenrecord, will never notice the broken pipe and terminate.
    // The shell protocol doesn't require a PTY because it's always monitoring the local socket FD
    // with select() and will send SIGHUP manually to the child process.
    if (protocol_ == SubprocessProtocol::kNone && type_ == SubprocessType::kRaw) {
        // Disable PTY input/output processing since the client is expecting raw data.
        D("Can't create raw subprocess without shell protocol, using PTY in raw mode instead");
        type_ = SubprocessType::kPty;
        make_pty_raw_ = true;
    }
}

Subprocess::~Subprocess() {
    WaitForExit();
}

static std::string GetHostName() {
    char buf[HOST_NAME_MAX];
    if (gethostname(buf, sizeof(buf)) != -1 && strcmp(buf, "localhost") != 0) return buf;

    return android::base::GetProperty("ro.product.device", "android");
}

bool Subprocess::ForkAndExec(std::string* error) {
    unique_fd child_stdinout_sfd, child_stderr_sfd;
    unique_fd parent_error_sfd, child_error_sfd;
    char pts_name[PATH_MAX];

    if (command_.empty()) {
        __android_log_security_bswrite(SEC_TAG_ADB_SHELL_INTERACTIVE, "");
    } else {
        __android_log_security_bswrite(SEC_TAG_ADB_SHELL_CMD, command_.c_str());
    }

    // Create a socketpair for the fork() child to report any errors back to the parent. Since we
    // use threads, logging directly from the child might deadlock due to locks held in another
    // thread during the fork.
    if (!CreateSocketpair(&parent_error_sfd, &child_error_sfd)) {
        *error = android::base::StringPrintf(
            "failed to create pipe for subprocess error reporting: %s", strerror(errno));
        return false;
    }

    // Construct the environment for the child before we fork.
    passwd* pw = getpwuid(getuid());
    std::unordered_map<std::string, std::string> env;
    if (environ) {
        char** current = environ;
        while (char* env_cstr = *current++) {
            std::string env_string = env_cstr;
            char* delimiter = strchr(&env_string[0], '=');

            // Drop any values that don't contain '='.
            if (delimiter) {
                *delimiter++ = '\0';
                env[env_string.c_str()] = delimiter;
            }
        }
    }

    if (pw != nullptr) {
        env["HOME"] = pw->pw_dir;
        env["HOSTNAME"] = GetHostName();
        env["LOGNAME"] = pw->pw_name;
        env["SHELL"] = pw->pw_shell;
        env["TMPDIR"] = "/data/local/tmp";
        env["USER"] = pw->pw_name;
    }

    if (!terminal_type_.empty()) {
        env["TERM"] = terminal_type_;
    }

    std::vector<std::string> joined_env;
    for (auto it : env) {
        const char* key = it.first.c_str();
        const char* value = it.second.c_str();
        joined_env.push_back(android::base::StringPrintf("%s=%s", key, value));
    }

    std::vector<const char*> cenv;
    for (const std::string& str : joined_env) {
        cenv.push_back(str.c_str());
    }
    cenv.push_back(nullptr);

    if (type_ == SubprocessType::kPty) {
        int fd;
        pid_ = forkpty(&fd, pts_name, nullptr, nullptr);
        if (pid_ > 0) {
          stdinout_sfd_.reset(fd);
        }
    } else {
        if (!CreateSocketpair(&stdinout_sfd_, &child_stdinout_sfd)) {
            *error = android::base::StringPrintf("failed to create socketpair for stdin/out: %s",
                                                 strerror(errno));
            return false;
        }
        // Raw subprocess + shell protocol allows for splitting stderr.
        if (protocol_ == SubprocessProtocol::kShell &&
                !CreateSocketpair(&stderr_sfd_, &child_stderr_sfd)) {
            *error = android::base::StringPrintf("failed to create socketpair for stderr: %s",
                                                 strerror(errno));
            return false;
        }
        pid_ = fork();
    }

    if (pid_ == -1) {
        *error = android::base::StringPrintf("fork failed: %s", strerror(errno));
        return false;
    }

    if (pid_ == 0) {
        // Subprocess child.
        setsid();

        if (type_ == SubprocessType::kPty) {
            child_stdinout_sfd.reset(OpenPtyChildFd(pts_name, &child_error_sfd));
        }

        dup2(child_stdinout_sfd, STDIN_FILENO);
        dup2(child_stdinout_sfd, STDOUT_FILENO);
        dup2(child_stderr_sfd != -1 ? child_stderr_sfd : child_stdinout_sfd, STDERR_FILENO);

        // exec doesn't trigger destructors, close the FDs manually.
        stdinout_sfd_.reset(-1);
        stderr_sfd_.reset(-1);
        child_stdinout_sfd.reset(-1);
        child_stderr_sfd.reset(-1);
        parent_error_sfd.reset(-1);
        close_on_exec(child_error_sfd);

        // adbd sets SIGPIPE to SIG_IGN to get EPIPE instead, and Linux propagates that to child
        // processes, so we need to manually reset back to SIG_DFL here (http://b/35209888).
        signal(SIGPIPE, SIG_DFL);

        // Increase oom_score_adj from -1000, so that the child is visible to the OOM-killer.
        // Don't treat failure as an error, because old Android kernels explicitly disabled this.
        int oom_score_adj_fd = adb_open("/proc/self/oom_score_adj", O_WRONLY | O_CLOEXEC);
        if (oom_score_adj_fd != -1) {
            const char* oom_score_adj_value = "-950";
            TEMP_FAILURE_RETRY(
                adb_write(oom_score_adj_fd, oom_score_adj_value, strlen(oom_score_adj_value)));
        }

#ifdef __ANDROID_RECOVERY__
        // Special routine for recovery. Switch to shell domain when adbd is
        // is running with dropped privileged (i.e. not running as root) and
        // is built for the recovery mode. This is required because recovery
        // rootfs is not labeled and everything is labeled just as rootfs.
        char* con = nullptr;
        if (getcon(&con) == 0) {
            if (!strcmp(con, "u:r:adbd:s0")) {
                if (selinux_android_setcon("u:r:shell:s0") < 0) {
                    LOG(FATAL) << "Could not set SELinux context for subprocess";
                }
            }
            freecon(con);
        } else {
            LOG(FATAL) << "Failed to get SELinux context";
        }
#endif

        if (command_.empty()) {
            // Spawn a login shell if we don't have a command.
            execle(_PATH_BSHELL, "-" _PATH_BSHELL, nullptr, cenv.data());
        } else {
            execle(_PATH_BSHELL, _PATH_BSHELL, "-c", command_.c_str(), nullptr, cenv.data());
        }
        WriteFdExactly(child_error_sfd, "exec '" _PATH_BSHELL "' failed: ");
        WriteFdExactly(child_error_sfd, strerror(errno));
        child_error_sfd.reset(-1);
        _Exit(1);
    }

    // Subprocess parent.
    D("subprocess parent: stdin/stdout FD = %d, stderr FD = %d",
      stdinout_sfd_.get(), stderr_sfd_.get());

    // Wait to make sure the subprocess exec'd without error.
    child_error_sfd.reset(-1);
    std::string error_message = ReadAll(parent_error_sfd);
    if (!error_message.empty()) {
        *error = error_message;
        return false;
    }

    D("subprocess parent: exec completed");
    if (protocol_ == SubprocessProtocol::kNone) {
        // No protocol: all streams pass through the stdinout FD and hook
        // directly into the local socket for raw data transfer.
        local_socket_sfd_.reset(stdinout_sfd_.release());
    } else {
        // Shell protocol: create another socketpair to intercept data.
        if (!CreateSocketpair(&protocol_sfd_, &local_socket_sfd_)) {
            *error = android::base::StringPrintf(
                "failed to create socketpair to intercept data: %s", strerror(errno));
            kill(pid_, SIGKILL);
            return false;
        }
        D("protocol FD = %d", protocol_sfd_.get());

        input_ = std::make_unique<ShellProtocol>(protocol_sfd_);
        output_ = std::make_unique<ShellProtocol>(protocol_sfd_);
        if (!input_ || !output_) {
            *error = "failed to allocate shell protocol objects";
            kill(pid_, SIGKILL);
            return false;
        }

        // Don't let reads/writes to the subprocess block our thread. This isn't
        // likely but could happen under unusual circumstances, such as if we
        // write a ton of data to stdin but the subprocess never reads it and
        // the pipe fills up.
        for (int fd : {stdinout_sfd_.get(), stderr_sfd_.get()}) {
            if (fd >= 0) {
                if (!set_file_block_mode(fd, false)) {
                    *error = android::base::StringPrintf(
                        "failed to set non-blocking mode for fd %d", fd);
                    kill(pid_, SIGKILL);
                    return false;
                }
            }
        }
    }

    D("subprocess parent: completed");
    return true;
}

bool Subprocess::StartThread(std::unique_ptr<Subprocess> subprocess, std::string* error) {
    Subprocess* raw = subprocess.release();
    std::thread(ThreadHandler, raw).detach();

    return true;
}

int Subprocess::OpenPtyChildFd(const char* pts_name, unique_fd* error_sfd) {
    int child_fd = adb_open(pts_name, O_RDWR | O_CLOEXEC);
    if (child_fd == -1) {
        // Don't use WriteFdFmt; since we're in the fork() child we don't want
        // to allocate any heap memory to avoid race conditions.
        const char* messages[] = {"child failed to open pseudo-term slave ",
                                  pts_name, ": ", strerror(errno)};
        for (const char* message : messages) {
            WriteFdExactly(*error_sfd, message);
        }
        abort();
    }

    if (make_pty_raw_) {
        termios tattr;
        if (tcgetattr(child_fd, &tattr) == -1) {
            int saved_errno = errno;
            WriteFdExactly(*error_sfd, "tcgetattr failed: ");
            WriteFdExactly(*error_sfd, strerror(saved_errno));
            abort();
        }

        cfmakeraw(&tattr);
        if (tcsetattr(child_fd, TCSADRAIN, &tattr) == -1) {
            int saved_errno = errno;
            WriteFdExactly(*error_sfd, "tcsetattr failed: ");
            WriteFdExactly(*error_sfd, strerror(saved_errno));
            abort();
        }
    }

    return child_fd;
}

void Subprocess::ThreadHandler(void* userdata) {
    Subprocess* subprocess = reinterpret_cast<Subprocess*>(userdata);

    adb_thread_setname(android::base::StringPrintf("shell svc %d", subprocess->pid()));

    D("passing data streams for PID %d", subprocess->pid());
    subprocess->PassDataStreams();

    D("deleting Subprocess for PID %d", subprocess->pid());
    delete subprocess;
}

void Subprocess::PassDataStreams() {
    if (protocol_sfd_ == -1) {
        return;
    }

    // Start by trying to read from the protocol FD, stdout, and stderr.
    fd_set master_read_set, master_write_set;
    FD_ZERO(&master_read_set);
    FD_ZERO(&master_write_set);
    for (unique_fd* sfd : {&protocol_sfd_, &stdinout_sfd_, &stderr_sfd_}) {
        if (*sfd != -1) {
            FD_SET(*sfd, &master_read_set);
        }
    }

    // Pass data until the protocol FD or both the subprocess pipes die, at
    // which point we can't pass any more data.
    while (protocol_sfd_ != -1 && (stdinout_sfd_ != -1 || stderr_sfd_ != -1)) {
        unique_fd* dead_sfd = SelectLoop(&master_read_set, &master_write_set);
        if (dead_sfd) {
            D("closing FD %d", dead_sfd->get());
            FD_CLR(*dead_sfd, &master_read_set);
            FD_CLR(*dead_sfd, &master_write_set);
            if (dead_sfd == &protocol_sfd_) {
                // Using SIGHUP is a decent general way to indicate that the
                // controlling process is going away. If specific signals are
                // needed (e.g. SIGINT), pass those through the shell protocol
                // and only fall back on this for unexpected closures.
                D("protocol FD died, sending SIGHUP to pid %d", pid_);
                kill(pid_, SIGHUP);

                // We also need to close the pipes connected to the child process
                // so that if it ignores SIGHUP and continues to write data it
                // won't fill up the pipe and block.
                stdinout_sfd_.reset();
                stderr_sfd_.reset();
            }
            dead_sfd->reset();
        }
    }
}

namespace {

inline bool ValidAndInSet(const unique_fd& sfd, fd_set* set) {
    return sfd != -1 && FD_ISSET(sfd, set);
}

}   // namespace

unique_fd* Subprocess::SelectLoop(fd_set* master_read_set_ptr,
                                  fd_set* master_write_set_ptr) {
    fd_set read_set, write_set;
    int select_n = std::max(std::max(protocol_sfd_, stdinout_sfd_), stderr_sfd_) + 1;
    unique_fd* dead_sfd = nullptr;

    // Keep calling select() and passing data until an FD closes/errors.
    while (!dead_sfd) {
        memcpy(&read_set, master_read_set_ptr, sizeof(read_set));
        memcpy(&write_set, master_write_set_ptr, sizeof(write_set));
        if (select(select_n, &read_set, &write_set, nullptr, nullptr) < 0) {
            if (errno == EINTR) {
                continue;
            } else {
                PLOG(ERROR) << "select failed, closing subprocess pipes";
                stdinout_sfd_.reset(-1);
                stderr_sfd_.reset(-1);
                return nullptr;
            }
        }

        // Read stdout, write to protocol FD.
        if (ValidAndInSet(stdinout_sfd_, &read_set)) {
            dead_sfd = PassOutput(&stdinout_sfd_, ShellProtocol::kIdStdout);
        }

        // Read stderr, write to protocol FD.
        if (!dead_sfd && ValidAndInSet(stderr_sfd_, &read_set)) {
            dead_sfd = PassOutput(&stderr_sfd_, ShellProtocol::kIdStderr);
        }

        // Read protocol FD, write to stdin.
        if (!dead_sfd && ValidAndInSet(protocol_sfd_, &read_set)) {
            dead_sfd = PassInput();
            // If we didn't finish writing, block on stdin write.
            if (input_bytes_left_) {
                FD_CLR(protocol_sfd_, master_read_set_ptr);
                FD_SET(stdinout_sfd_, master_write_set_ptr);
            }
        }

        // Continue writing to stdin; only happens if a previous write blocked.
        if (!dead_sfd && ValidAndInSet(stdinout_sfd_, &write_set)) {
            dead_sfd = PassInput();
            // If we finished writing, go back to blocking on protocol read.
            if (!input_bytes_left_) {
                FD_SET(protocol_sfd_, master_read_set_ptr);
                FD_CLR(stdinout_sfd_, master_write_set_ptr);
            }
        }
    }  // while (!dead_sfd)

    return dead_sfd;
}

unique_fd* Subprocess::PassInput() {
    // Only read a new packet if we've finished writing the last one.
    if (!input_bytes_left_) {
        if (!input_->Read()) {
            // Read() uses ReadFdExactly() which sets errno to 0 on EOF.
            if (errno != 0) {
                PLOG(ERROR) << "error reading protocol FD " << protocol_sfd_;
            }
            return &protocol_sfd_;
        }

        if (stdinout_sfd_ != -1) {
            switch (input_->id()) {
                case ShellProtocol::kIdWindowSizeChange:
                    int rows, cols, x_pixels, y_pixels;
                    if (sscanf(input_->data(), "%dx%d,%dx%d",
                               &rows, &cols, &x_pixels, &y_pixels) == 4) {
                        winsize ws;
                        ws.ws_row = rows;
                        ws.ws_col = cols;
                        ws.ws_xpixel = x_pixels;
                        ws.ws_ypixel = y_pixels;
                        ioctl(stdinout_sfd_, TIOCSWINSZ, &ws);
                    }
                    break;
                case ShellProtocol::kIdStdin:
                    input_bytes_left_ = input_->data_length();
                    break;
                case ShellProtocol::kIdCloseStdin:
                    if (type_ == SubprocessType::kRaw) {
                        if (adb_shutdown(stdinout_sfd_, SHUT_WR) == 0) {
                            return nullptr;
                        }
                        PLOG(ERROR) << "failed to shutdown writes to FD "
                                    << stdinout_sfd_;
                        return &stdinout_sfd_;
                    } else {
                        // PTYs can't close just input, so rather than close the
                        // FD and risk losing subprocess output, leave it open.
                        // This only happens if the client starts a PTY shell
                        // non-interactively which is rare and unsupported.
                        // If necessary, the client can manually close the shell
                        // with `exit` or by killing the adb client process.
                        D("can't close input for PTY FD %d", stdinout_sfd_.get());
                    }
                    break;
            }
        }
    }

    if (input_bytes_left_ > 0) {
        int index = input_->data_length() - input_bytes_left_;
        int bytes = adb_write(stdinout_sfd_, input_->data() + index, input_bytes_left_);
        if (bytes == 0 || (bytes < 0 && errno != EAGAIN)) {
            if (bytes < 0) {
                PLOG(ERROR) << "error reading stdin FD " << stdinout_sfd_;
            }
            // stdin is done, mark this packet as finished and we'll just start
            // dumping any further data received from the protocol FD.
            input_bytes_left_ = 0;
            return &stdinout_sfd_;
        } else if (bytes > 0) {
            input_bytes_left_ -= bytes;
        }
    }

    return nullptr;
}

unique_fd* Subprocess::PassOutput(unique_fd* sfd, ShellProtocol::Id id) {
    int bytes = adb_read(*sfd, output_->data(), output_->data_capacity());
    if (bytes == 0 || (bytes < 0 && errno != EAGAIN)) {
        // read() returns EIO if a PTY closes; don't report this as an error,
        // it just means the subprocess completed.
        if (bytes < 0 && !(type_ == SubprocessType::kPty && errno == EIO)) {
            PLOG(ERROR) << "error reading output FD " << *sfd;
        }
        return sfd;
    }

    if (bytes > 0 && !output_->Write(id, bytes)) {
        if (errno != 0) {
            PLOG(ERROR) << "error reading protocol FD " << protocol_sfd_;
        }
        return &protocol_sfd_;
    }

    return nullptr;
}

void Subprocess::WaitForExit() {
    int exit_code = 1;

    D("waiting for pid %d", pid_);
    while (true) {
        int status;
        if (pid_ == waitpid(pid_, &status, 0)) {
            D("post waitpid (pid=%d) status=%04x", pid_, status);
            if (WIFSIGNALED(status)) {
                exit_code = 0x80 | WTERMSIG(status);
                D("subprocess killed by signal %d", WTERMSIG(status));
                break;
            } else if (!WIFEXITED(status)) {
                D("subprocess didn't exit");
                break;
            } else if (WEXITSTATUS(status) >= 0) {
                exit_code = WEXITSTATUS(status);
                D("subprocess exit code = %d", WEXITSTATUS(status));
                break;
            }
        }
    }

    // If we have an open protocol FD send an exit packet.
    if (protocol_sfd_ != -1) {
        output_->data()[0] = exit_code;
        if (output_->Write(ShellProtocol::kIdExit, 1)) {
            D("wrote the exit code packet: %d", exit_code);
        } else {
            PLOG(ERROR) << "failed to write the exit code packet";
        }
        protocol_sfd_.reset(-1);
    }
}

}  // namespace

// Create a pipe containing the error.
static int ReportError(SubprocessProtocol protocol, const std::string& message) {
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        LOG(ERROR) << "failed to create pipe to report error";
        return -1;
    }

    std::string buf = android::base::StringPrintf("error: %s\n", message.c_str());
    if (protocol == SubprocessProtocol::kShell) {
        ShellProtocol::Id id = ShellProtocol::kIdStderr;
        uint32_t length = buf.length();
        WriteFdExactly(pipefd[1], &id, sizeof(id));
        WriteFdExactly(pipefd[1], &length, sizeof(length));
    }

    WriteFdExactly(pipefd[1], buf.data(), buf.length());

    if (protocol == SubprocessProtocol::kShell) {
        ShellProtocol::Id id = ShellProtocol::kIdExit;
        uint32_t length = 1;
        char exit_code = 126;
        WriteFdExactly(pipefd[1], &id, sizeof(id));
        WriteFdExactly(pipefd[1], &length, sizeof(length));
        WriteFdExactly(pipefd[1], &exit_code, sizeof(exit_code));
    }

    adb_close(pipefd[1]);
    return pipefd[0];
}

int StartSubprocess(const char* name, const char* terminal_type,
                    SubprocessType type, SubprocessProtocol protocol) {
    D("starting %s subprocess (protocol=%s, TERM=%s): '%s'",
      type == SubprocessType::kRaw ? "raw" : "PTY",
      protocol == SubprocessProtocol::kNone ? "none" : "shell",
      terminal_type, name);

    auto subprocess = std::make_unique<Subprocess>(name, terminal_type, type, protocol);
    if (!subprocess) {
        LOG(ERROR) << "failed to allocate new subprocess";
        return ReportError(protocol, "failed to allocate new subprocess");
    }

    std::string error;
    if (!subprocess->ForkAndExec(&error)) {
        LOG(ERROR) << "failed to start subprocess: " << error;
        return ReportError(protocol, error);
    }

    unique_fd local_socket(subprocess->ReleaseLocalSocket());
    D("subprocess creation successful: local_socket_fd=%d, pid=%d", local_socket.get(),
      subprocess->pid());

    if (!Subprocess::StartThread(std::move(subprocess), &error)) {
        LOG(ERROR) << "failed to start subprocess management thread: " << error;
        return ReportError(protocol, error);
    }

    return local_socket.release();
}

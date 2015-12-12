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
#include <pty.h>
#include <pwd.h>
#include <sys/select.h>
#include <termios.h>

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <paths.h>

#include "adb.h"
#include "adb_io.h"
#include "adb_trace.h"
#include "adb_utils.h"

namespace {

void init_subproc_child()
{
    setsid();

    // Set OOM score adjustment to prevent killing
    int fd = adb_open("/proc/self/oom_score_adj", O_WRONLY | O_CLOEXEC);
    if (fd >= 0) {
        adb_write(fd, "0", 1);
        adb_close(fd);
    } else {
       D("adb: unable to update oom_score_adj");
    }
}

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

// Helper to automatically close an FD when it goes out of scope.
class ScopedFd {
  public:
    ScopedFd() {}
    ~ScopedFd() { Reset(); }

    void Reset(int fd=-1) {
        if (fd != fd_) {
            if (valid()) {
                adb_close(fd_);
            }
            fd_ = fd;
        }
    }

    int Release() {
        int temp = fd_;
        fd_ = -1;
        return temp;
    }

    bool valid() const { return fd_ >= 0; }

    int fd() const { return fd_; }

  private:
    int fd_ = -1;

    DISALLOW_COPY_AND_ASSIGN(ScopedFd);
};

// Creates a socketpair and saves the endpoints to |fd1| and |fd2|.
bool CreateSocketpair(ScopedFd* fd1, ScopedFd* fd2) {
    int sockets[2];
    if (adb_socketpair(sockets) < 0) {
        PLOG(ERROR) << "cannot create socket pair";
        return false;
    }
    fd1->Reset(sockets[0]);
    fd2->Reset(sockets[1]);
    return true;
}

class Subprocess {
  public:
    Subprocess(const std::string& command, const char* terminal_type,
               SubprocessType type, SubprocessProtocol protocol);
    ~Subprocess();

    const std::string& command() const { return command_; }
    bool is_interactive() const { return command_.empty(); }

    int local_socket_fd() const { return local_socket_sfd_.fd(); }

    pid_t pid() const { return pid_; }

    // Sets up FDs, forks a subprocess, starts the subprocess manager thread,
    // and exec's the child. Returns false on failure.
    bool ForkAndExec();

  private:
    // Opens the file at |pts_name|.
    int OpenPtyChildFd(const char* pts_name, ScopedFd* error_sfd);

    static void* ThreadHandler(void* userdata);
    void PassDataStreams();
    void WaitForExit();

    ScopedFd* SelectLoop(fd_set* master_read_set_ptr,
                         fd_set* master_write_set_ptr);

    // Input/output stream handlers. Success returns nullptr, failure returns
    // a pointer to the failed FD.
    ScopedFd* PassInput();
    ScopedFd* PassOutput(ScopedFd* sfd, ShellProtocol::Id id);

    const std::string command_;
    const std::string terminal_type_;
    SubprocessType type_;
    SubprocessProtocol protocol_;
    pid_t pid_ = -1;
    ScopedFd local_socket_sfd_;

    // Shell protocol variables.
    ScopedFd stdinout_sfd_, stderr_sfd_, protocol_sfd_;
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
}

Subprocess::~Subprocess() {
}

bool Subprocess::ForkAndExec() {
    ScopedFd child_stdinout_sfd, child_stderr_sfd;
    ScopedFd parent_error_sfd, child_error_sfd;
    char pts_name[PATH_MAX];

    // Create a socketpair for the fork() child to report any errors back to the parent. Since we
    // use threads, logging directly from the child might deadlock due to locks held in another
    // thread during the fork.
    if (!CreateSocketpair(&parent_error_sfd, &child_error_sfd)) {
        LOG(ERROR) << "failed to create pipe for subprocess error reporting";
    }

    // Construct the environment for the child before we fork.
    passwd* pw = getpwuid(getuid());
    std::unordered_map<std::string, std::string> env;
    if (environ) {
        char** current = environ;
        while (char* env_cstr = *current++) {
            std::string env_string = env_cstr;
            char* delimiter = strchr(env_string.c_str(), '=');

            // Drop any values that don't contain '='.
            if (delimiter) {
                *delimiter++ = '\0';
                env[env_string.c_str()] = delimiter;
            }
        }
    }

    if (pw != nullptr) {
        // TODO: $HOSTNAME? Normally bash automatically sets that, but mksh doesn't.
        env["HOME"] = pw->pw_dir;
        env["LOGNAME"] = pw->pw_name;
        env["USER"] = pw->pw_name;
        env["SHELL"] = pw->pw_shell;
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
        stdinout_sfd_.Reset(fd);
    } else {
        if (!CreateSocketpair(&stdinout_sfd_, &child_stdinout_sfd)) {
            return false;
        }
        // Raw subprocess + shell protocol allows for splitting stderr.
        if (protocol_ == SubprocessProtocol::kShell &&
                !CreateSocketpair(&stderr_sfd_, &child_stderr_sfd)) {
            return false;
        }
        pid_ = fork();
    }

    if (pid_ == -1) {
        PLOG(ERROR) << "fork failed";
        return false;
    }

    if (pid_ == 0) {
        // Subprocess child.
        init_subproc_child();

        if (type_ == SubprocessType::kPty) {
            child_stdinout_sfd.Reset(OpenPtyChildFd(pts_name, &child_error_sfd));
        }

        dup2(child_stdinout_sfd.fd(), STDIN_FILENO);
        dup2(child_stdinout_sfd.fd(), STDOUT_FILENO);
        dup2(child_stderr_sfd.valid() ? child_stderr_sfd.fd() : child_stdinout_sfd.fd(),
             STDERR_FILENO);

        // exec doesn't trigger destructors, close the FDs manually.
        stdinout_sfd_.Reset();
        stderr_sfd_.Reset();
        child_stdinout_sfd.Reset();
        child_stderr_sfd.Reset();
        parent_error_sfd.Reset();
        close_on_exec(child_error_sfd.fd());

        if (is_interactive()) {
            execle(_PATH_BSHELL, _PATH_BSHELL, "-", nullptr, cenv.data());
        } else {
            execle(_PATH_BSHELL, _PATH_BSHELL, "-c", command_.c_str(), nullptr, cenv.data());
        }
        WriteFdExactly(child_error_sfd.fd(), "exec '" _PATH_BSHELL "' failed");
        child_error_sfd.Reset();
        _Exit(1);
    }

    // Subprocess parent.
    D("subprocess parent: stdin/stdout FD = %d, stderr FD = %d",
      stdinout_sfd_.fd(), stderr_sfd_.fd());

    // Wait to make sure the subprocess exec'd without error.
    child_error_sfd.Reset();
    std::string error_message = ReadAll(parent_error_sfd.fd());
    if (!error_message.empty()) {
        LOG(ERROR) << error_message;
        return false;
    }

    D("subprocess parent: exec completed");
    if (protocol_ == SubprocessProtocol::kNone) {
        // No protocol: all streams pass through the stdinout FD and hook
        // directly into the local socket for raw data transfer.
        local_socket_sfd_.Reset(stdinout_sfd_.Release());
    } else {
        // Shell protocol: create another socketpair to intercept data.
        if (!CreateSocketpair(&protocol_sfd_, &local_socket_sfd_)) {
            return false;
        }
        D("protocol FD = %d", protocol_sfd_.fd());

        input_.reset(new ShellProtocol(protocol_sfd_.fd()));
        output_.reset(new ShellProtocol(protocol_sfd_.fd()));
        if (!input_ || !output_) {
            LOG(ERROR) << "failed to allocate shell protocol objects";
            return false;
        }

        // Don't let reads/writes to the subprocess block our thread. This isn't
        // likely but could happen under unusual circumstances, such as if we
        // write a ton of data to stdin but the subprocess never reads it and
        // the pipe fills up.
        for (int fd : {stdinout_sfd_.fd(), stderr_sfd_.fd()}) {
            if (fd >= 0) {
                if (!set_file_block_mode(fd, false)) {
                    LOG(ERROR) << "failed to set non-blocking mode for fd " << fd;
                    return false;
                }
            }
        }
    }

    if (!adb_thread_create(ThreadHandler, this)) {
        PLOG(ERROR) << "failed to create subprocess thread";
        return false;
    }

    D("subprocess parent: completed");
    return true;
}

int Subprocess::OpenPtyChildFd(const char* pts_name, ScopedFd* error_sfd) {
    int child_fd = adb_open(pts_name, O_RDWR | O_CLOEXEC);
    if (child_fd == -1) {
        // Don't use WriteFdFmt; since we're in the fork() child we don't want
        // to allocate any heap memory to avoid race conditions.
        const char* messages[] = {"child failed to open pseudo-term slave ",
                                  pts_name, ": ", strerror(errno)};
        for (const char* message : messages) {
            WriteFdExactly(error_sfd->fd(), message);
        }
        exit(-1);
    }

    if (!is_interactive()) {
        termios tattr;
        if (tcgetattr(child_fd, &tattr) == -1) {
            WriteFdExactly(error_sfd->fd(), "tcgetattr failed");
            exit(-1);
        }

        cfmakeraw(&tattr);
        if (tcsetattr(child_fd, TCSADRAIN, &tattr) == -1) {
            WriteFdExactly(error_sfd->fd(), "tcsetattr failed");
            exit(-1);
        }
    }

    return child_fd;
}

void* Subprocess::ThreadHandler(void* userdata) {
    Subprocess* subprocess = reinterpret_cast<Subprocess*>(userdata);

    adb_thread_setname(android::base::StringPrintf(
            "shell srvc %d", subprocess->local_socket_fd()));

    subprocess->PassDataStreams();
    subprocess->WaitForExit();

    D("deleting Subprocess for PID %d", subprocess->pid());
    delete subprocess;

    return nullptr;
}

void Subprocess::PassDataStreams() {
    if (!protocol_sfd_.valid()) {
        return;
    }

    // Start by trying to read from the protocol FD, stdout, and stderr.
    fd_set master_read_set, master_write_set;
    FD_ZERO(&master_read_set);
    FD_ZERO(&master_write_set);
    for (ScopedFd* sfd : {&protocol_sfd_, &stdinout_sfd_, &stderr_sfd_}) {
        if (sfd->valid()) {
            FD_SET(sfd->fd(), &master_read_set);
        }
    }

    // Pass data until the protocol FD or both the subprocess pipes die, at
    // which point we can't pass any more data.
    while (protocol_sfd_.valid() &&
            (stdinout_sfd_.valid() || stderr_sfd_.valid())) {
        ScopedFd* dead_sfd = SelectLoop(&master_read_set, &master_write_set);
        if (dead_sfd) {
            D("closing FD %d", dead_sfd->fd());
            FD_CLR(dead_sfd->fd(), &master_read_set);
            FD_CLR(dead_sfd->fd(), &master_write_set);
            if (dead_sfd == &protocol_sfd_) {
                // Using SIGHUP is a decent general way to indicate that the
                // controlling process is going away. If specific signals are
                // needed (e.g. SIGINT), pass those through the shell protocol
                // and only fall back on this for unexpected closures.
                D("protocol FD died, sending SIGHUP to pid %d", pid_);
                kill(pid_, SIGHUP);
            }
            dead_sfd->Reset();
        }
    }
}

namespace {

inline bool ValidAndInSet(const ScopedFd& sfd, fd_set* set) {
    return sfd.valid() && FD_ISSET(sfd.fd(), set);
}

}   // namespace

ScopedFd* Subprocess::SelectLoop(fd_set* master_read_set_ptr,
                                 fd_set* master_write_set_ptr) {
    fd_set read_set, write_set;
    int select_n = std::max(std::max(protocol_sfd_.fd(), stdinout_sfd_.fd()),
                            stderr_sfd_.fd()) + 1;
    ScopedFd* dead_sfd = nullptr;

    // Keep calling select() and passing data until an FD closes/errors.
    while (!dead_sfd) {
        memcpy(&read_set, master_read_set_ptr, sizeof(read_set));
        memcpy(&write_set, master_write_set_ptr, sizeof(write_set));
        if (select(select_n, &read_set, &write_set, nullptr, nullptr) < 0) {
            if (errno == EINTR) {
                continue;
            } else {
                PLOG(ERROR) << "select failed, closing subprocess pipes";
                stdinout_sfd_.Reset();
                stderr_sfd_.Reset();
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
                FD_CLR(protocol_sfd_.fd(), master_read_set_ptr);
                FD_SET(stdinout_sfd_.fd(), master_write_set_ptr);
            }
        }

        // Continue writing to stdin; only happens if a previous write blocked.
        if (!dead_sfd && ValidAndInSet(stdinout_sfd_, &write_set)) {
            dead_sfd = PassInput();
            // If we finished writing, go back to blocking on protocol read.
            if (!input_bytes_left_) {
                FD_SET(protocol_sfd_.fd(), master_read_set_ptr);
                FD_CLR(stdinout_sfd_.fd(), master_write_set_ptr);
            }
        }
    }  // while (!dead_sfd)

    return dead_sfd;
}

ScopedFd* Subprocess::PassInput() {
    // Only read a new packet if we've finished writing the last one.
    if (!input_bytes_left_) {
        if (!input_->Read()) {
            // Read() uses ReadFdExactly() which sets errno to 0 on EOF.
            if (errno != 0) {
                PLOG(ERROR) << "error reading protocol FD "
                            << protocol_sfd_.fd();
            }
            return &protocol_sfd_;
        }

        if (stdinout_sfd_.valid()) {
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
                        ioctl(stdinout_sfd_.fd(), TIOCSWINSZ, &ws);
                    }
                    break;
                case ShellProtocol::kIdStdin:
                    input_bytes_left_ = input_->data_length();
                    break;
                case ShellProtocol::kIdCloseStdin:
                    if (type_ == SubprocessType::kRaw) {
                        if (adb_shutdown(stdinout_sfd_.fd(), SHUT_WR) == 0) {
                            return nullptr;
                        }
                        PLOG(ERROR) << "failed to shutdown writes to FD "
                                    << stdinout_sfd_.fd();
                        return &stdinout_sfd_;
                    } else {
                        // PTYs can't close just input, so rather than close the
                        // FD and risk losing subprocess output, leave it open.
                        // This only happens if the client starts a PTY shell
                        // non-interactively which is rare and unsupported.
                        // If necessary, the client can manually close the shell
                        // with `exit` or by killing the adb client process.
                        D("can't close input for PTY FD %d", stdinout_sfd_.fd());
                    }
                    break;
            }
        }
    }

    if (input_bytes_left_ > 0) {
        int index = input_->data_length() - input_bytes_left_;
        int bytes = adb_write(stdinout_sfd_.fd(), input_->data() + index,
                              input_bytes_left_);
        if (bytes == 0 || (bytes < 0 && errno != EAGAIN)) {
            if (bytes < 0) {
                PLOG(ERROR) << "error reading stdin FD " << stdinout_sfd_.fd();
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

ScopedFd* Subprocess::PassOutput(ScopedFd* sfd, ShellProtocol::Id id) {
    int bytes = adb_read(sfd->fd(), output_->data(), output_->data_capacity());
    if (bytes == 0 || (bytes < 0 && errno != EAGAIN)) {
        // read() returns EIO if a PTY closes; don't report this as an error,
        // it just means the subprocess completed.
        if (bytes < 0 && !(type_ == SubprocessType::kPty && errno == EIO)) {
            PLOG(ERROR) << "error reading output FD " << sfd->fd();
        }
        return sfd;
    }

    if (bytes > 0 && !output_->Write(id, bytes)) {
        if (errno != 0) {
            PLOG(ERROR) << "error reading protocol FD " << protocol_sfd_.fd();
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
    if (protocol_sfd_.valid()) {
        output_->data()[0] = exit_code;
        if (output_->Write(ShellProtocol::kIdExit, 1)) {
            D("wrote the exit code packet: %d", exit_code);
        } else {
            PLOG(ERROR) << "failed to write the exit code packet";
        }
        protocol_sfd_.Reset();
    }

    // Pass the local socket FD to the shell cleanup fdevent.
    if (SHELL_EXIT_NOTIFY_FD >= 0) {
        int fd = local_socket_sfd_.fd();
        if (WriteFdExactly(SHELL_EXIT_NOTIFY_FD, &fd, sizeof(fd))) {
            D("passed fd %d to SHELL_EXIT_NOTIFY_FD (%d) for pid %d",
              fd, SHELL_EXIT_NOTIFY_FD, pid_);
            // The shell exit fdevent now owns the FD and will close it once
            // the last bit of data flushes through.
            local_socket_sfd_.Release();
        } else {
            PLOG(ERROR) << "failed to write fd " << fd
                        << " to SHELL_EXIT_NOTIFY_FD (" << SHELL_EXIT_NOTIFY_FD
                        << ") for pid " << pid_;
        }
    }
}

}  // namespace

int StartSubprocess(const char* name, const char* terminal_type,
                    SubprocessType type, SubprocessProtocol protocol) {
    D("starting %s subprocess (protocol=%s, TERM=%s): '%s'",
      type == SubprocessType::kRaw ? "raw" : "PTY",
      protocol == SubprocessProtocol::kNone ? "none" : "shell",
      terminal_type, name);

    Subprocess* subprocess = new Subprocess(name, terminal_type, type, protocol);
    if (!subprocess) {
        LOG(ERROR) << "failed to allocate new subprocess";
        return -1;
    }

    if (!subprocess->ForkAndExec()) {
        LOG(ERROR) << "failed to start subprocess";
        delete subprocess;
        return -1;
    }

    D("subprocess creation successful: local_socket_fd=%d, pid=%d",
      subprocess->local_socket_fd(), subprocess->pid());
    return subprocess->local_socket_fd();
}

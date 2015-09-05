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

#define TRACE_TAG TRACE_SHELL

#include "shell_service.h"

#if !ADB_HOST

#include <errno.h>
#include <pty.h>
#include <termios.h>

#include <base/logging.h>
#include <base/stringprintf.h>
#include <paths.h>

#include "adb.h"
#include "adb_io.h"
#include "adb_trace.h"
#include "sysdeps.h"

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
    Subprocess(const std::string& command, SubprocessType type);
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
    void WaitForExit();

    const std::string command_;
    SubprocessType type_;

    pid_t pid_ = -1;
    ScopedFd local_socket_sfd_;

    DISALLOW_COPY_AND_ASSIGN(Subprocess);
};

Subprocess::Subprocess(const std::string& command, SubprocessType type)
        : command_(command), type_(type) {
}

Subprocess::~Subprocess() {
}

bool Subprocess::ForkAndExec() {
    ScopedFd parent_sfd, child_sfd, parent_error_sfd, child_error_sfd;
    char pts_name[PATH_MAX];

    // Create a socketpair for the fork() child to report any errors back to
    // the parent. Since we use threads, logging directly from the child could
    // create a race condition.
    if (!CreateSocketpair(&parent_error_sfd, &child_error_sfd)) {
        LOG(ERROR) << "failed to create pipe for subprocess error reporting";
    }

    if (type_ == SubprocessType::kPty) {
        int fd;
        pid_ = forkpty(&fd, pts_name, nullptr, nullptr);
        parent_sfd.Reset(fd);
    } else {
        if (!CreateSocketpair(&parent_sfd, &child_sfd)) {
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
            child_sfd.Reset(OpenPtyChildFd(pts_name, &child_error_sfd));
        }

        dup2(child_sfd.fd(), STDIN_FILENO);
        dup2(child_sfd.fd(), STDOUT_FILENO);
        dup2(child_sfd.fd(), STDERR_FILENO);

        // exec doesn't trigger destructors, close the FDs manually.
        parent_sfd.Reset();
        child_sfd.Reset();
        parent_error_sfd.Reset();
        close_on_exec(child_error_sfd.fd());

        if (is_interactive()) {
            execl(_PATH_BSHELL, _PATH_BSHELL, "-", nullptr);
        } else {
            execl(_PATH_BSHELL, _PATH_BSHELL, "-c", command_.c_str(), nullptr);
        }
        WriteFdExactly(child_error_sfd.fd(), "exec '" _PATH_BSHELL "' failed");
        child_error_sfd.Reset();
        exit(-1);
    }

    // Subprocess parent.
    D("subprocess parent: subprocess FD = %d", parent_sfd.fd());

    // Wait to make sure the subprocess exec'd without error.
    child_error_sfd.Reset();
    std::string error_message = ReadAll(parent_error_sfd.fd());
    if (!error_message.empty()) {
        LOG(ERROR) << error_message;
        return false;
    }

    local_socket_sfd_.Reset(parent_sfd.Release());

    if (!adb_thread_create(ThreadHandler, this)) {
        PLOG(ERROR) << "failed to create subprocess thread";
        return false;
    }

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

    subprocess->WaitForExit();

    D("deleting Subprocess");
    delete subprocess;

    return nullptr;
}

void Subprocess::WaitForExit() {
    D("waiting for pid %d", pid_);
    while (true) {
        int status;
        if (pid_ == waitpid(pid_, &status, 0)) {
            D("post waitpid (pid=%d) status=%04x", pid_, status);
            if (WIFSIGNALED(status)) {
                D("subprocess killed by signal %d", WTERMSIG(status));
                break;
            } else if (!WIFEXITED(status)) {
                D("subprocess didn't exit");
                break;
            } else if (WEXITSTATUS(status) >= 0) {
                D("subprocess exit code = %d", WEXITSTATUS(status));
                break;
            }
        }
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

int StartSubprocess(const char *name, SubprocessType type) {
    D("starting %s subprocess: '%s'",
      type == SubprocessType::kRaw ? "raw" : "PTY", name);

    Subprocess* subprocess = new Subprocess(name, type);
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

#endif  // !ADB_HOST

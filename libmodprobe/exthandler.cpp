/*
 * Copyright (C) 2024 The Android Open Source Project
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

#include <exthandler/exthandler.h>

#include <android-base/chrono_utils.h>
#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <fnmatch.h>
#include <grp.h>
#include <pwd.h>
#include <sys/wait.h>

using android::base::ErrnoError;
using android::base::Error;
using android::base::ReadFdToString;
using android::base::Result;
using android::base::Split;
using android::base::Trim;
using android::base::unique_fd;

Result<std::string> RunExternalHandler(const std::string& handler, uid_t uid, gid_t gid,
                                       std::unordered_map<std::string, std::string>& envs_map) {
    unique_fd child_stdout;
    unique_fd parent_stdout;
    if (!Socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, &child_stdout, &parent_stdout)) {
        return ErrnoError() << "Socketpair() for stdout failed";
    }

    unique_fd child_stderr;
    unique_fd parent_stderr;
    if (!Socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, &child_stderr, &parent_stderr)) {
        return ErrnoError() << "Socketpair() for stderr failed";
    }

    signal(SIGCHLD, SIG_DFL);

    auto pid = fork();
    if (pid < 0) {
        return ErrnoError() << "fork() failed";
    }

    if (pid == 0) {
        for (auto it = envs_map.begin(); it != envs_map.end(); ++it) {
            setenv(it->first.c_str(), it->second.c_str(), 1);
        }
        parent_stdout.reset();
        parent_stderr.reset();
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
        dup2(child_stdout.get(), STDOUT_FILENO);
        dup2(child_stderr.get(), STDERR_FILENO);

        auto args = Split(handler, " ");
        std::vector<char*> c_args;
        for (auto& arg : args) {
            c_args.emplace_back(arg.data());
        }
        c_args.emplace_back(nullptr);

        if (gid != 0) {
            if (setgid(gid) != 0) {
                fprintf(stderr, "setgid() failed: %s", strerror(errno));
                _exit(EXIT_FAILURE);
            }
        }

        if (setuid(uid) != 0) {
            fprintf(stderr, "setuid() failed: %s", strerror(errno));
            _exit(EXIT_FAILURE);
        }

        execv(c_args[0], c_args.data());
        fprintf(stderr, "exec() failed: %s", strerror(errno));
        _exit(EXIT_FAILURE);
    }

    child_stdout.reset();
    child_stderr.reset();

    int status;
    pid_t waited_pid = TEMP_FAILURE_RETRY(waitpid(pid, &status, 0));
    if (waited_pid == -1) {
        return ErrnoError() << "waitpid() failed";
    }

    std::string stdout_content;
    if (!ReadFdToString(parent_stdout.get(), &stdout_content)) {
        return ErrnoError() << "ReadFdToString() for stdout failed";
    }

    std::string stderr_content;
    if (ReadFdToString(parent_stderr.get(), &stderr_content)) {
        auto messages = Split(stderr_content, "\n");
        for (const auto& message : messages) {
            if (!message.empty()) {
                LOG(ERROR) << "External Handler: " << message;
            }
        }
    } else {
        LOG(ERROR) << "ReadFdToString() for stderr failed";
    }

    if (WIFEXITED(status)) {
        if (WEXITSTATUS(status) == EXIT_SUCCESS) {
            return Trim(stdout_content);
        } else {
            return Error() << "exited with status " << WEXITSTATUS(status);
        }
    } else if (WIFSIGNALED(status)) {
        return Error() << "killed by signal " << WTERMSIG(status);
    }

    return Error() << "unexpected exit status " << status;
}

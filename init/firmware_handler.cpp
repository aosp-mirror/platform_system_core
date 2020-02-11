/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include "firmware_handler.h"

#include <fcntl.h>
#include <pwd.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/wait.h>
#include <unistd.h>

#include <thread>

#include <android-base/chrono_utils.h>
#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>

using android::base::ReadFdToString;
using android::base::Socketpair;
using android::base::Split;
using android::base::Timer;
using android::base::Trim;
using android::base::unique_fd;
using android::base::WriteFully;

namespace android {
namespace init {

static void LoadFirmware(const std::string& firmware, const std::string& root, int fw_fd,
                         size_t fw_size, int loading_fd, int data_fd) {
    // Start transfer.
    WriteFully(loading_fd, "1", 1);

    // Copy the firmware.
    int rc = sendfile(data_fd, fw_fd, nullptr, fw_size);
    if (rc == -1) {
        PLOG(ERROR) << "firmware: sendfile failed { '" << root << "', '" << firmware << "' }";
    }

    // Tell the firmware whether to abort or commit.
    const char* response = (rc != -1) ? "0" : "-1";
    WriteFully(loading_fd, response, strlen(response));
}

static bool IsBooting() {
    return access("/dev/.booting", F_OK) == 0;
}

FirmwareHandler::FirmwareHandler(std::vector<std::string> firmware_directories,
                                 std::vector<ExternalFirmwareHandler> external_firmware_handlers)
    : firmware_directories_(std::move(firmware_directories)),
      external_firmware_handlers_(std::move(external_firmware_handlers)) {}

Result<std::string> FirmwareHandler::RunExternalHandler(const std::string& handler, uid_t uid,
                                                        const Uevent& uevent) const {
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
        setenv("FIRMWARE", uevent.firmware.c_str(), 1);
        setenv("DEVPATH", uevent.path.c_str(), 1);
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
                LOG(ERROR) << "External Firmware Handler: " << message;
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

std::string FirmwareHandler::GetFirmwarePath(const Uevent& uevent) const {
    for (const auto& external_handler : external_firmware_handlers_) {
        if (external_handler.devpath == uevent.path) {
            LOG(INFO) << "Launching external firmware handler '" << external_handler.handler_path
                      << "' for devpath: '" << uevent.path << "' firmware: '" << uevent.firmware
                      << "'";

            auto result =
                    RunExternalHandler(external_handler.handler_path, external_handler.uid, uevent);
            if (!result.ok()) {
                LOG(ERROR) << "Using default firmware; External firmware handler failed: "
                           << result.error();
                return uevent.firmware;
            }
            if (result->find("..") != std::string::npos) {
                LOG(ERROR) << "Using default firmware; External firmware handler provided an "
                              "invalid path, '"
                           << *result << "'";
                return uevent.firmware;
            }
            LOG(INFO) << "Loading firmware '" << *result << "' in place of '" << uevent.firmware
                      << "'";
            return *result;
        }
    }
    LOG(INFO) << "firmware: loading '" << uevent.firmware << "' for '" << uevent.path << "'";
    return uevent.firmware;
}

void FirmwareHandler::ProcessFirmwareEvent(const std::string& root,
                                           const std::string& firmware) const {
    std::string loading = root + "/loading";
    std::string data = root + "/data";

    unique_fd loading_fd(open(loading.c_str(), O_WRONLY | O_CLOEXEC));
    if (loading_fd == -1) {
        PLOG(ERROR) << "couldn't open firmware loading fd for " << firmware;
        return;
    }

    unique_fd data_fd(open(data.c_str(), O_WRONLY | O_CLOEXEC));
    if (data_fd == -1) {
        PLOG(ERROR) << "couldn't open firmware data fd for " << firmware;
        return;
    }

    std::vector<std::string> attempted_paths_and_errors;

    int booting = IsBooting();
try_loading_again:
    attempted_paths_and_errors.clear();
    for (const auto& firmware_directory : firmware_directories_) {
        std::string file = firmware_directory + firmware;
        unique_fd fw_fd(open(file.c_str(), O_RDONLY | O_CLOEXEC));
        if (fw_fd == -1) {
            attempted_paths_and_errors.emplace_back("firmware: attempted " + file +
                                                    ", open failed: " + strerror(errno));
            continue;
        }
        struct stat sb;
        if (fstat(fw_fd, &sb) == -1) {
            attempted_paths_and_errors.emplace_back("firmware: attempted " + file +
                                                    ", fstat failed: " + strerror(errno));
            continue;
        }
        LoadFirmware(firmware, root, fw_fd, sb.st_size, loading_fd, data_fd);
        return;
    }

    if (booting) {
        // If we're not fully booted, we may be missing
        // filesystems needed for firmware, wait and retry.
        std::this_thread::sleep_for(100ms);
        booting = IsBooting();
        goto try_loading_again;
    }

    LOG(ERROR) << "firmware: could not find firmware for " << firmware;
    for (const auto& message : attempted_paths_and_errors) {
        LOG(ERROR) << message;
    }

    // Write "-1" as our response to the kernel's firmware request, since we have nothing for it.
    write(loading_fd, "-1", 2);
}

void FirmwareHandler::HandleUevent(const Uevent& uevent) {
    if (uevent.subsystem != "firmware" || uevent.action != "add") return;

    // Loading the firmware in a child means we can do that in parallel...
    auto pid = fork();
    if (pid == -1) {
        PLOG(ERROR) << "could not fork to process firmware event for " << uevent.firmware;
    }
    if (pid == 0) {
        Timer t;
        auto firmware = GetFirmwarePath(uevent);
        ProcessFirmwareEvent("/sys" + uevent.path, firmware);
        LOG(INFO) << "loading " << uevent.path << " took " << t;
        _exit(EXIT_SUCCESS);
    }
}

}  // namespace init
}  // namespace android

/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include "adb.h"
#include "adb_io.h"
#include "adb_unique_fd.h"
#include "adb_utils.h"
#include "shell_service.h"

#include <android-base/cmsg.h>

namespace {

struct AbbProcess;
static auto& abbp = *new std::unique_ptr<AbbProcess>(std::make_unique<AbbProcess>());

struct AbbProcess {
    unique_fd sendCommand(std::string_view command);

  private:
    static unique_fd startAbbProcess(unique_fd* error_fd);

    static constexpr auto kRetries = 2;
    static constexpr auto kErrorProtocol = SubprocessProtocol::kShell;

    std::mutex locker_;
    unique_fd socket_fd_;
};

unique_fd AbbProcess::sendCommand(std::string_view command) {
    std::unique_lock lock{locker_};

    for (int i = 0; i < kRetries; ++i) {
        unique_fd error_fd;
        if (socket_fd_ == -1) {
            socket_fd_ = startAbbProcess(&error_fd);
        }
        if (socket_fd_ == -1) {
            LOG(ERROR) << "failed to start abb process";
            return error_fd;
        }

        if (!SendProtocolString(socket_fd_, std::string(command))) {
            PLOG(ERROR) << "failed to send command to abb";
            socket_fd_.reset();
            continue;
        }

        unique_fd fd;
        std::string error;
        char buf;
        if (android::base::ReceiveFileDescriptors(socket_fd_, &buf, 1, &fd) != 1) {
            PLOG(ERROR) << "failed to receive FD from abb";
            socket_fd_.reset();
            continue;
        }

        return fd;
    }

    LOG(ERROR) << "abb is unavailable";
    socket_fd_.reset();
    return ReportError(kErrorProtocol, "abb is unavailable");
}

unique_fd AbbProcess::startAbbProcess(unique_fd* error_fd) {
    constexpr auto abb_process_type = SubprocessType::kRaw;
    constexpr auto abb_protocol = SubprocessProtocol::kNone;
    constexpr auto make_pty_raw = false;
    return StartSubprocess("abb", "dumb", abb_process_type, abb_protocol, make_pty_raw,
                           kErrorProtocol, error_fd);
}

}  // namespace

unique_fd execute_binder_command(std::string_view command) {
    return abbp->sendCommand(command);
}

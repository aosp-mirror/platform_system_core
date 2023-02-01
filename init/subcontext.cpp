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

#include "subcontext.h"

#include <fcntl.h>
#include <poll.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <selinux/android.h>

#include "action.h"
#include "builtins.h"
#include "mount_namespace.h"
#include "proto_utils.h"
#include "util.h"

#ifdef INIT_FULL_SOURCES
#include <android/api-level.h>
#include "property_service.h"
#include "selabel.h"
#include "selinux.h"
#else
#include "host_init_stubs.h"
#endif

using android::base::GetExecutablePath;
using android::base::GetProperty;
using android::base::Join;
using android::base::Socketpair;
using android::base::Split;
using android::base::StartsWith;
using android::base::unique_fd;

namespace android {
namespace init {
namespace {

std::string shutdown_command;
static bool subcontext_terminated_by_shutdown;
static std::unique_ptr<Subcontext> subcontext;

class SubcontextProcess {
  public:
    SubcontextProcess(const BuiltinFunctionMap* function_map, std::string context, int init_fd)
        : function_map_(function_map), context_(std::move(context)), init_fd_(init_fd){};
    void MainLoop();

  private:
    void RunCommand(const SubcontextCommand::ExecuteCommand& execute_command,
                    SubcontextReply* reply) const;
    void ExpandArgs(const SubcontextCommand::ExpandArgsCommand& expand_args_command,
                    SubcontextReply* reply) const;

    const BuiltinFunctionMap* function_map_;
    const std::string context_;
    const int init_fd_;
};

void SubcontextProcess::RunCommand(const SubcontextCommand::ExecuteCommand& execute_command,
                                   SubcontextReply* reply) const {
    // Need to use ArraySplice instead of this code.
    auto args = std::vector<std::string>();
    for (const auto& string : execute_command.args()) {
        args.emplace_back(string);
    }

    auto map_result = function_map_->Find(args);
    Result<void> result;
    if (!map_result.ok()) {
        result = Error() << "Cannot find command: " << map_result.error();
    } else {
        result = RunBuiltinFunction(map_result->function, args, context_);
    }

    if (result.ok()) {
        reply->set_success(true);
    } else {
        auto* failure = reply->mutable_failure();
        failure->set_error_string(result.error().message());
        failure->set_error_errno(result.error().code());
    }
}

void SubcontextProcess::ExpandArgs(const SubcontextCommand::ExpandArgsCommand& expand_args_command,
                                   SubcontextReply* reply) const {
    for (const auto& arg : expand_args_command.args()) {
        auto expanded_arg = ExpandProps(arg);
        if (!expanded_arg.ok()) {
            auto* failure = reply->mutable_failure();
            failure->set_error_string(expanded_arg.error().message());
            failure->set_error_errno(0);
            return;
        } else {
            auto* expand_args_reply = reply->mutable_expand_args_reply();
            expand_args_reply->add_expanded_args(*expanded_arg);
        }
    }
}

void SubcontextProcess::MainLoop() {
    pollfd ufd[1];
    ufd[0].events = POLLIN;
    ufd[0].fd = init_fd_;

    while (true) {
        ufd[0].revents = 0;
        int nr = TEMP_FAILURE_RETRY(poll(ufd, arraysize(ufd), -1));
        if (nr == 0) continue;
        if (nr < 0) {
            PLOG(FATAL) << "poll() of subcontext socket failed, continuing";
        }

        auto init_message = ReadMessage(init_fd_);
        if (!init_message.ok()) {
            if (init_message.error().code() == 0) {
                // If the init file descriptor was closed, let's exit quietly. If
                // this was accidental, init will restart us. If init died, this
                // avoids calling abort(3) unnecessarily.
                return;
            }
            LOG(FATAL) << "Could not read message from init: " << init_message.error();
        }

        auto subcontext_command = SubcontextCommand();
        if (!subcontext_command.ParseFromString(*init_message)) {
            LOG(FATAL) << "Unable to parse message from init";
        }

        auto reply = SubcontextReply();
        switch (subcontext_command.command_case()) {
            case SubcontextCommand::kExecuteCommand: {
                RunCommand(subcontext_command.execute_command(), &reply);
                break;
            }
            case SubcontextCommand::kExpandArgsCommand: {
                ExpandArgs(subcontext_command.expand_args_command(), &reply);
                break;
            }
            default:
                LOG(FATAL) << "Unknown message type from init: "
                           << subcontext_command.command_case();
        }

        if (!shutdown_command.empty()) {
            reply.set_trigger_shutdown(shutdown_command);
            shutdown_command.clear();
        }

        if (auto result = SendMessage(init_fd_, reply); !result.ok()) {
            LOG(FATAL) << "Failed to send message to init: " << result.error();
        }
    }
}

}  // namespace

int SubcontextMain(int argc, char** argv, const BuiltinFunctionMap* function_map) {
    if (argc < 4) LOG(FATAL) << "Fewer than 4 args specified to subcontext (" << argc << ")";

    auto context = std::string(argv[2]);
    auto init_fd = std::atoi(argv[3]);

    SelabelInitialize();

    trigger_shutdown = [](const std::string& command) { shutdown_command = command; };

    auto subcontext_process = SubcontextProcess(function_map, context, init_fd);
    // Restore prio before main loop
    setpriority(PRIO_PROCESS, 0, 0);
    subcontext_process.MainLoop();
    return 0;
}

void Subcontext::Fork() {
    unique_fd subcontext_socket;
    if (!Socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, &socket_, &subcontext_socket)) {
        LOG(FATAL) << "Could not create socket pair to communicate to subcontext";
        return;
    }

    auto result = fork();

    if (result == -1) {
        LOG(FATAL) << "Could not fork subcontext";
    } else if (result == 0) {
        socket_.reset();

        // We explicitly do not use O_CLOEXEC here, such that we can reference this FD by number
        // in the subcontext process after we exec.
        int child_fd = dup(subcontext_socket.get());  // NOLINT(android-cloexec-dup)
        if (child_fd < 0) {
            PLOG(FATAL) << "Could not dup child_fd";
        }

        // We don't switch contexts if we're running the unit tests.  We don't use std::optional,
        // since we still need a real context string to pass to the builtin functions.
        if (context_ != kTestContext) {
            if (setexeccon(context_.c_str()) < 0) {
                PLOG(FATAL) << "Could not set execcon for '" << context_ << "'";
            }
        }
#if defined(__ANDROID__)
        // subcontext init runs in "default" mount namespace
        // so that it can access /apex/*
        if (auto result = SwitchToMountNamespaceIfNeeded(NS_DEFAULT); !result.ok()) {
            LOG(FATAL) << "Could not switch to \"default\" mount namespace: " << result.error();
        }
#endif
        auto init_path = GetExecutablePath();
        auto child_fd_string = std::to_string(child_fd);
        const char* args[] = {init_path.c_str(), "subcontext", context_.c_str(),
                              child_fd_string.c_str(), nullptr};
        execv(init_path.data(), const_cast<char**>(args));

        PLOG(FATAL) << "Could not execv subcontext init";
    } else {
        subcontext_socket.reset();
        pid_ = result;
        LOG(INFO) << "Forked subcontext for '" << context_ << "' with pid " << pid_;
    }
}

void Subcontext::Restart() {
    LOG(ERROR) << "Restarting subcontext '" << context_ << "'";
    if (pid_) {
        kill(pid_, SIGKILL);
    }
    pid_ = 0;
    socket_.reset();
    Fork();
}

bool Subcontext::PathMatchesSubcontext(const std::string& path) const {
    auto apex_name = GetApexNameFromFileName(path);
    if (!apex_name.empty()) {
        return std::find(apex_list_.begin(), apex_list_.end(), apex_name) != apex_list_.end();
    }
    for (const auto& prefix : path_prefixes_) {
        if (StartsWith(path, prefix)) {
            return true;
        }
    }
    return false;
}

void Subcontext::SetApexList(std::vector<std::string>&& apex_list) {
    apex_list_ = std::move(apex_list);
}

Result<SubcontextReply> Subcontext::TransmitMessage(const SubcontextCommand& subcontext_command) {
    if (auto result = SendMessage(socket_.get(), subcontext_command); !result.ok()) {
        Restart();
        return ErrnoError() << "Failed to send message to subcontext";
    }

    auto subcontext_message = ReadMessage(socket_.get());
    if (!subcontext_message.ok()) {
        Restart();
        return Error() << "Failed to receive result from subcontext: " << subcontext_message.error();
    }

    auto subcontext_reply = SubcontextReply{};
    if (!subcontext_reply.ParseFromString(*subcontext_message)) {
        Restart();
        return Error() << "Unable to parse message from subcontext";
    }

    if (subcontext_reply.has_trigger_shutdown()) {
        trigger_shutdown(subcontext_reply.trigger_shutdown());
    }

    return subcontext_reply;
}

Result<void> Subcontext::Execute(const std::vector<std::string>& args) {
    auto subcontext_command = SubcontextCommand();
    std::copy(
        args.begin(), args.end(),
        RepeatedPtrFieldBackInserter(subcontext_command.mutable_execute_command()->mutable_args()));

    auto subcontext_reply = TransmitMessage(subcontext_command);
    if (!subcontext_reply.ok()) {
        return subcontext_reply.error();
    }

    if (subcontext_reply->reply_case() == SubcontextReply::kFailure) {
        auto& failure = subcontext_reply->failure();
        return ResultError<>(failure.error_string(), failure.error_errno());
    }

    if (subcontext_reply->reply_case() != SubcontextReply::kSuccess) {
        return Error() << "Unexpected message type from subcontext: "
                       << subcontext_reply->reply_case();
    }

    return {};
}

Result<std::vector<std::string>> Subcontext::ExpandArgs(const std::vector<std::string>& args) {
    auto subcontext_command = SubcontextCommand{};
    std::copy(args.begin(), args.end(),
              RepeatedPtrFieldBackInserter(
                  subcontext_command.mutable_expand_args_command()->mutable_args()));

    auto subcontext_reply = TransmitMessage(subcontext_command);
    if (!subcontext_reply.ok()) {
        return subcontext_reply.error();
    }

    if (subcontext_reply->reply_case() == SubcontextReply::kFailure) {
        auto& failure = subcontext_reply->failure();
        return ResultError<>(failure.error_string(), failure.error_errno());
    }

    if (subcontext_reply->reply_case() != SubcontextReply::kExpandArgsReply) {
        return Error() << "Unexpected message type from subcontext: "
                       << subcontext_reply->reply_case();
    }

    auto& reply = subcontext_reply->expand_args_reply();
    auto expanded_args = std::vector<std::string>{};
    for (const auto& string : reply.expanded_args()) {
        expanded_args.emplace_back(string);
    }
    return expanded_args;
}

void InitializeSubcontext() {
    if (IsMicrodroid()) {
        LOG(INFO) << "Not using subcontext for microdroid";
        return;
    }

    if (SelinuxGetVendorAndroidVersion() >= __ANDROID_API_P__) {
        subcontext.reset(
                new Subcontext(std::vector<std::string>{"/vendor", "/odm"}, kVendorContext));
    }
}
void InitializeHostSubcontext(std::vector<std::string> vendor_prefixes) {
    subcontext.reset(new Subcontext(vendor_prefixes, kVendorContext, /*host=*/true));
}

Subcontext* GetSubcontext() {
    return subcontext.get();
}

bool SubcontextChildReap(pid_t pid) {
    if (!subcontext) {
        return false;
    }
    if (subcontext->pid() == pid) {
        if (!subcontext_terminated_by_shutdown) {
            subcontext->Restart();
        }
        return true;
    }
    return false;
}

void SubcontextTerminate() {
    if (!subcontext) {
        return;
    }
    subcontext_terminated_by_shutdown = true;
    kill(subcontext->pid(), SIGTERM);
}

}  // namespace init
}  // namespace android

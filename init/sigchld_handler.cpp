/*
 * Copyright (C) 2010 The Android Open Source Project
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

#include "sigchld_handler.h"

#include <signal.h>
#include <string.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <android-base/chrono_utils.h>
#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/scopeguard.h>
#include <android-base/stringprintf.h>

#include <thread>

#include "epoll.h"
#include "init.h"
#include "service.h"
#include "service_list.h"

using android::base::boot_clock;
using android::base::make_scope_guard;
using android::base::ReadFileToString;
using android::base::StringPrintf;
using android::base::Timer;

namespace android {
namespace init {

static pid_t ReapOneProcess() {
    siginfo_t siginfo = {};
    // This returns a zombie pid or informs us that there are no zombies left to be reaped.
    // It does NOT reap the pid; that is done below.
    if (TEMP_FAILURE_RETRY(waitid(P_ALL, 0, &siginfo, WEXITED | WNOHANG | WNOWAIT)) != 0) {
        PLOG(ERROR) << "waitid failed";
        return 0;
    }

    const pid_t pid = siginfo.si_pid;
    if (pid == 0) {
        DCHECK_EQ(siginfo.si_signo, 0);
        return 0;
    }

    DCHECK_EQ(siginfo.si_signo, SIGCHLD);

    // At this point we know we have a zombie pid, so we use this scopeguard to reap the pid
    // whenever the function returns from this point forward.
    // We do NOT want to reap the zombie earlier as in Service::Reap(), we kill(-pid, ...) and we
    // want the pid to remain valid throughout that (and potentially future) usages.
    auto reaper = make_scope_guard([pid] { TEMP_FAILURE_RETRY(waitpid(pid, nullptr, WNOHANG)); });

    std::string name;
    std::string wait_string;
    Service* service = nullptr;

    if (SubcontextChildReap(pid)) {
        name = "Subcontext";
    } else {
        service = ServiceList::GetInstance().FindService(pid, &Service::pid);

        if (service) {
            name = StringPrintf("Service '%s' (pid %d)", service->name().c_str(), pid);
            if (service->flags() & SVC_EXEC) {
                auto exec_duration = boot_clock::now() - service->time_started();
                auto exec_duration_ms =
                    std::chrono::duration_cast<std::chrono::milliseconds>(exec_duration).count();
                wait_string = StringPrintf(" waiting took %f seconds", exec_duration_ms / 1000.0f);
            } else if (service->flags() & SVC_ONESHOT) {
                auto exec_duration = boot_clock::now() - service->time_started();
                auto exec_duration_ms =
                        std::chrono::duration_cast<std::chrono::milliseconds>(exec_duration)
                                .count();
                wait_string = StringPrintf(" oneshot service took %f seconds in background",
                                           exec_duration_ms / 1000.0f);
            }
        } else {
            name = StringPrintf("Untracked pid %d", pid);
        }
    }

    if (siginfo.si_code == CLD_EXITED) {
        LOG(INFO) << name << " exited with status " << siginfo.si_status << wait_string;
    } else {
        LOG(INFO) << name << " received signal " << siginfo.si_status << wait_string;
    }

    if (!service) {
        LOG(INFO) << name << " did not have an associated service entry and will not be reaped";
        return pid;
    }

    service->Reap(siginfo);

    if (service->flags() & SVC_TEMPORARY) {
        ServiceList::GetInstance().RemoveService(*service);
    }

    return pid;
}

std::set<pid_t> ReapAnyOutstandingChildren() {
    std::set<pid_t> reaped_pids;
    for (;;) {
        const pid_t pid = ReapOneProcess();
        if (pid <= 0) {
            return reaped_pids;
        }
        reaped_pids.emplace(pid);
    }
}

static void ReapAndRemove(std::vector<pid_t>& alive_pids) {
    for (auto pid : ReapAnyOutstandingChildren()) {
        const auto it = std::find(alive_pids.begin(), alive_pids.end(), pid);
        if (it != alive_pids.end()) {
            alive_pids.erase(it);
        }
    }
}

static void HandleSignal(int signal_fd) {
    signalfd_siginfo siginfo;
    ssize_t bytes_read = TEMP_FAILURE_RETRY(read(signal_fd, &siginfo, sizeof(siginfo)));
    if (bytes_read != sizeof(siginfo)) {
        LOG(WARNING) << "Unexpected: " << __func__ << " read " << bytes_read << " bytes instead of "
                     << sizeof(siginfo);
    }
}

void WaitToBeReaped(int sigchld_fd, const std::vector<pid_t>& pids,
                    std::chrono::milliseconds timeout) {
    Timer t;
    Epoll epoll;
    if (sigchld_fd >= 0) {
        if (auto result = epoll.Open(); result.ok()) {
            result =
                    epoll.RegisterHandler(sigchld_fd, [sigchld_fd]() { HandleSignal(sigchld_fd); });
            if (!result.ok()) {
                LOG(WARNING) << __func__
                             << " RegisterHandler() failed. Falling back to sleep_for(): "
                             << result.error();
                sigchld_fd = -1;
            }
        } else {
            LOG(WARNING) << __func__ << " Epoll::Open() failed. Falling back to sleep_for(): "
                         << result.error();
            sigchld_fd = -1;
        }
    }
    std::vector<pid_t> alive_pids(pids);
    ReapAndRemove(alive_pids);
    while (!alive_pids.empty() && t.duration() < timeout) {
        if (sigchld_fd >= 0) {
            auto result = epoll.Wait(std::max(timeout - t.duration(), 0ms));
            if (result.ok()) {
                ReapAndRemove(alive_pids);
                continue;
            } else {
                LOG(WARNING) << "Epoll::Wait() failed " << result.error();
            }
        }
        std::this_thread::sleep_for(50ms);
        ReapAndRemove(alive_pids);
    }
    LOG(INFO) << "Waiting for " << pids.size() << " pids to be reaped took " << t << " with "
              << alive_pids.size() << " of them still running";
    for (pid_t pid : alive_pids) {
        std::string status = "(no-such-pid)";
        ReadFileToString(StringPrintf("/proc/%d/status", pid), &status);
        LOG(INFO) << "Still running: " << pid << '\n' << status;
    }
}

}  // namespace init
}  // namespace android

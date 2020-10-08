/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <android-base/logging.h>
#include <libsnapshot/snapuserd_daemon.h>

namespace android {
namespace snapshot {

int Daemon::StartServer(std::string socketname) {
    int ret;

    ret = server_.Start(socketname);
    if (ret < 0) {
        LOG(ERROR) << "Snapuserd daemon failed to start...";
        exit(EXIT_FAILURE);
    }

    return ret;
}

void Daemon::MaskAllSignalsExceptIntAndTerm() {
    sigset_t signal_mask;
    sigfillset(&signal_mask);
    sigdelset(&signal_mask, SIGINT);
    sigdelset(&signal_mask, SIGTERM);
    sigdelset(&signal_mask, SIGPIPE);
    if (sigprocmask(SIG_SETMASK, &signal_mask, NULL) != 0) {
        PLOG(ERROR) << "Failed to set sigprocmask";
    }
}

void Daemon::MaskAllSignals() {
    sigset_t signal_mask;
    sigfillset(&signal_mask);
    if (sigprocmask(SIG_SETMASK, &signal_mask, NULL) != 0) {
        PLOG(ERROR) << "Couldn't mask all signals";
    }
}

Daemon::Daemon() {
    is_running_ = true;
}

bool Daemon::IsRunning() {
    return is_running_;
}

void Daemon::Run() {
    poll_fd_ = std::make_unique<struct pollfd>();
    poll_fd_->fd = server_.GetSocketFd().get();
    poll_fd_->events = POLLIN;

    sigfillset(&signal_mask_);
    sigdelset(&signal_mask_, SIGINT);
    sigdelset(&signal_mask_, SIGTERM);

    // Masking signals here ensure that after this point, we won't handle INT/TERM
    // until after we call into ppoll()
    MaskAllSignals();
    signal(SIGINT, Daemon::SignalHandler);
    signal(SIGTERM, Daemon::SignalHandler);
    signal(SIGPIPE, Daemon::SignalHandler);

    LOG(DEBUG) << "Snapuserd-server: ready to accept connections";

    while (IsRunning()) {
        int ret = ppoll(poll_fd_.get(), 1, nullptr, &signal_mask_);
        MaskAllSignalsExceptIntAndTerm();

        if (ret == -1) {
            PLOG(ERROR) << "Snapuserd:ppoll error";
            break;
        }

        if (poll_fd_->revents == POLLIN) {
            if (server_.AcceptClient() == static_cast<int>(DaemonOperations::STOP)) {
                Daemon::Instance().is_running_ = false;
            }
        }

        // Mask all signals to ensure that is_running_ can't become false between
        // checking it in the while condition and calling into ppoll()
        MaskAllSignals();
    }
}

void Daemon::SignalHandler(int signal) {
    LOG(DEBUG) << "Snapuserd received signal: " << signal;
    switch (signal) {
        case SIGINT:
        case SIGTERM: {
            Daemon::Instance().is_running_ = false;
            break;
        }
        case SIGPIPE: {
            LOG(ERROR) << "Received SIGPIPE signal";
            break;
        }
        default:
            LOG(ERROR) << "Received unknown signal " << signal;
            break;
    }
}

}  // namespace snapshot
}  // namespace android

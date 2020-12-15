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

#include "snapuserd_daemon.h"

#include <android-base/logging.h>
#include <android-base/strings.h>
#include <gflags/gflags.h>
#include <libsnapshot/snapuserd_client.h>

#include "snapuserd_server.h"

DEFINE_string(socket, android::snapshot::kSnapuserdSocket, "Named socket or socket path.");
DEFINE_bool(no_socket, false,
            "If true, no socket is used. Each additional argument is an INIT message.");

namespace android {
namespace snapshot {

bool Daemon::StartServer(int argc, char** argv) {
    int arg_start = gflags::ParseCommandLineFlags(&argc, &argv, true);

    if (!FLAGS_no_socket) {
        return server_.Start(FLAGS_socket);
    }

    for (int i = arg_start; i < argc; i++) {
        auto parts = android::base::Split(argv[i], ",");
        if (parts.size() != 3) {
            LOG(ERROR) << "Malformed message, expected three sub-arguments.";
            return false;
        }
        auto handler = server_.AddHandler(parts[0], parts[1], parts[2]);
        if (!handler || !server_.StartHandler(handler)) {
            return false;
        }
    }

    // Skip the accept() call to avoid spurious log spam. The server will still
    // run until all handlers have completed.
    server_.SetTerminating();
    return true;
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

void Daemon::Run() {
    sigfillset(&signal_mask_);
    sigdelset(&signal_mask_, SIGINT);
    sigdelset(&signal_mask_, SIGTERM);

    // Masking signals here ensure that after this point, we won't handle INT/TERM
    // until after we call into ppoll()
    signal(SIGINT, Daemon::SignalHandler);
    signal(SIGTERM, Daemon::SignalHandler);
    signal(SIGPIPE, Daemon::SignalHandler);

    LOG(DEBUG) << "Snapuserd-server: ready to accept connections";

    MaskAllSignalsExceptIntAndTerm();

    server_.Run();
}

void Daemon::Interrupt() {
    server_.Interrupt();
}

void Daemon::SignalHandler(int signal) {
    LOG(DEBUG) << "Snapuserd received signal: " << signal;
    switch (signal) {
        case SIGINT:
        case SIGTERM: {
            Daemon::Instance().Interrupt();
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

int main(int argc, char** argv) {
    android::base::InitLogging(argv, &android::base::KernelLogger);

    android::snapshot::Daemon& daemon = android::snapshot::Daemon::Instance();

    if (!daemon.StartServer(argc, argv)) {
        LOG(ERROR) << "Snapuserd daemon failed to start.";
        exit(EXIT_FAILURE);
    }
    daemon.Run();

    return 0;
}

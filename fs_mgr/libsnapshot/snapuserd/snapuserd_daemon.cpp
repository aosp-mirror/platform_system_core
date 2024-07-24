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
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <gflags/gflags.h>
#include <snapuserd/snapuserd_client.h>

#include "snapuserd_daemon.h"

DEFINE_string(socket, android::snapshot::kSnapuserdSocket, "Named socket or socket path.");
DEFINE_bool(no_socket, false,
            "If true, no socket is used. Each additional argument is an INIT message.");
DEFINE_bool(socket_handoff, false,
            "If true, perform a socket hand-off with an existing snapuserd instance, then exit.");
DEFINE_bool(user_snapshot, false, "If true, user-space snapshots are used");
DEFINE_bool(io_uring, false, "If true, io_uring feature is enabled");
DEFINE_bool(o_direct, false, "If true, enable direct reads on source device");

namespace android {
namespace snapshot {

bool Daemon::IsUserspaceSnapshotsEnabled() {
    const std::string UNKNOWN = "unknown";
    const std::string vendor_release =
            android::base::GetProperty("ro.vendor.build.version.release_or_codename", UNKNOWN);

    // If the vendor is on Android S, install process will forcefully take the
    // userspace snapshots path.
    //
    // We will not reach here post OTA reboot as the binary will be from vendor
    // ramdisk which is on Android S.
    if (vendor_release.find("12") != std::string::npos) {
        LOG(INFO) << "Userspace snapshots enabled as vendor partition is on Android: "
                  << vendor_release;
        return true;
    }

    return android::base::GetBoolProperty("ro.virtual_ab.userspace.snapshots.enabled", false);
}

bool Daemon::StartDaemon(int argc, char** argv) {
    int arg_start = gflags::ParseCommandLineFlags(&argc, &argv, true);

    // Daemon launched from first stage init and during selinux transition
    // will have the command line "-user_snapshot" flag set if the user-space
    // snapshots are enabled.
    //
    // Daemon launched as a init service during "socket-handoff" and when OTA
    // is applied will check for the property. This is ok as the system
    // properties are valid at this point. We can't do this during first
    // stage init and hence use the command line flags to get the information.
    bool user_snapshots = FLAGS_user_snapshot;
    if (!user_snapshots) {
        user_snapshots = IsUserspaceSnapshotsEnabled();
    }
    if (user_snapshots) {
        LOG(INFO) << "Starting daemon for user-space snapshots.....";
        return StartServerForUserspaceSnapshots(arg_start, argc, argv);
    } else {
        LOG(ERROR) << "Userspace snapshots not enabled. No support for legacy snapshots";
    }
    return false;
}

bool Daemon::StartServerForUserspaceSnapshots(int arg_start, int argc, char** argv) {
    sigfillset(&signal_mask_);
    sigdelset(&signal_mask_, SIGINT);
    sigdelset(&signal_mask_, SIGTERM);
    sigdelset(&signal_mask_, SIGUSR1);

    // Masking signals here ensure that after this point, we won't handle INT/TERM
    // until after we call into ppoll()
    signal(SIGINT, Daemon::SignalHandler);
    signal(SIGTERM, Daemon::SignalHandler);
    signal(SIGPIPE, Daemon::SignalHandler);
    signal(SIGUSR1, Daemon::SignalHandler);

    MaskAllSignalsExceptIntAndTerm();

    user_server_.SetServerRunning();
    if (FLAGS_io_uring) {
        user_server_.SetIouringEnabled();
    }

    if (FLAGS_socket_handoff) {
        return user_server_.RunForSocketHandoff();
    }
    if (!FLAGS_no_socket) {
        if (!user_server_.Start(FLAGS_socket)) {
            return false;
        }
        return user_server_.Run();
    }

    for (int i = arg_start; i < argc; i++) {
        auto parts = android::base::Split(argv[i], ",");

        if (parts.size() != 4) {
            LOG(ERROR) << "Malformed message, expected at least four sub-arguments.";
            return false;
        }
        auto handler =
                user_server_.AddHandler(parts[0], parts[1], parts[2], parts[3], FLAGS_o_direct);
        if (!handler || !user_server_.StartHandler(parts[0])) {
            return false;
        }
    }

    // We reach this point only during selinux transition during device boot.
    // At this point, all threads are spin up and are ready to serve the I/O
    // requests for dm-user. Lets inform init.
    auto client = std::make_unique<SnapuserdClient>();
    client->NotifyTransitionDaemonIsReady();

    // Skip the accept() call to avoid spurious log spam. The server will still
    // run until all handlers have completed.
    return user_server_.WaitForSocket();
}

void Daemon::MaskAllSignalsExceptIntAndTerm() {
    sigset_t signal_mask;
    sigfillset(&signal_mask);
    sigdelset(&signal_mask, SIGINT);
    sigdelset(&signal_mask, SIGTERM);
    sigdelset(&signal_mask, SIGPIPE);
    sigdelset(&signal_mask, SIGUSR1);
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

void Daemon::Interrupt() {
    // TODO: We cannot access system property during first stage init.
    // Until we remove the dm-snapshot code, we will have this check
    // and verify it through a temp variable.
    if (user_server_.IsServerRunning()) {
        user_server_.Interrupt();
    }
}

void Daemon::ReceivedSocketSignal() {
    if (user_server_.IsServerRunning()) {
        user_server_.ReceivedSocketSignal();
    }
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
        case SIGUSR1: {
            LOG(INFO) << "Received SIGUSR1, attaching to proxy socket";
            Daemon::Instance().ReceivedSocketSignal();
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

    if (!daemon.StartDaemon(argc, argv)) {
        LOG(ERROR) << "Snapuserd daemon failed to start";
        exit(EXIT_FAILURE);
    }

    return 0;
}

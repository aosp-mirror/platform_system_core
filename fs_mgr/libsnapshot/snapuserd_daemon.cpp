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

Daemon::Daemon() {
    is_running_ = true;
    // TODO: Mask other signals - Bug 168258493
    signal(SIGINT, Daemon::SignalHandler);
    signal(SIGTERM, Daemon::SignalHandler);
}

bool Daemon::IsRunning() {
    return is_running_;
}

void Daemon::Run() {
    while (IsRunning()) {
        if (server_.AcceptClient() == static_cast<int>(DaemonOperations::STOP)) {
            Daemon::Instance().is_running_ = false;
        }
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
        default:
            LOG(ERROR) << "Received unknown signal " << signal;
            break;
    }
}

}  // namespace snapshot
}  // namespace android

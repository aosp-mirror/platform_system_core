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

#include "snapuserd_transition.h"

#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <unistd.h>

#include <filesystem>
#include <string>
#include <string_view>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <cutils/sockets.h>
#include <fs_avb/fs_avb.h>
#include <libsnapshot/snapshot.h>
#include <private/android_filesystem_config.h>
#include <procinfo/process_map.h>
#include <selinux/android.h>
#include <snapuserd/snapuserd_client.h>

#include "block_dev_initializer.h"
#include "lmkd_service.h"
#include "service_utils.h"
#include "util.h"

namespace android {
namespace init {

using namespace std::string_literals;

using android::base::unique_fd;
using android::snapshot::SnapshotManager;
using android::snapshot::SnapuserdClient;

static constexpr char kSnapuserdPath[] = "/system/bin/snapuserd";
static constexpr char kSnapuserdFirstStagePidVar[] = "FIRST_STAGE_SNAPUSERD_PID";
static constexpr char kSnapuserdFirstStageFdVar[] = "FIRST_STAGE_SNAPUSERD_FD";
static constexpr char kSnapuserdFirstStageInfoVar[] = "FIRST_STAGE_SNAPUSERD_INFO";
static constexpr char kSnapuserdLabel[] = "u:object_r:snapuserd_exec:s0";
static constexpr char kSnapuserdSocketLabel[] = "u:object_r:snapuserd_socket:s0";

void LaunchFirstStageSnapuserd(SnapshotDriver driver) {
    SocketDescriptor socket_desc;
    socket_desc.name = android::snapshot::kSnapuserdSocket;
    socket_desc.type = SOCK_STREAM;
    socket_desc.perm = 0660;
    socket_desc.uid = AID_SYSTEM;
    socket_desc.gid = AID_SYSTEM;

    // We specify a label here even though it technically is not needed. During
    // first_stage_mount there is no sepolicy loaded. Once sepolicy is loaded,
    // we bypass the socket entirely.
    auto socket = socket_desc.Create(kSnapuserdSocketLabel);
    if (!socket.ok()) {
        LOG(FATAL) << "Could not create snapuserd socket: " << socket.error();
    }

    pid_t pid = fork();
    if (pid < 0) {
        PLOG(FATAL) << "Cannot launch snapuserd; fork failed";
    }
    if (pid == 0) {
        socket->Publish();

        if (driver == SnapshotDriver::DM_USER) {
            char arg0[] = "/system/bin/snapuserd";
            char arg1[] = "-user_snapshot";
            char* const argv[] = {arg0, arg1, nullptr};
            if (execv(arg0, argv) < 0) {
                PLOG(FATAL) << "Cannot launch snapuserd; execv failed";
            }
            _exit(127);
        } else {
            char arg0[] = "/system/bin/snapuserd";
            char* const argv[] = {arg0, nullptr};
            if (execv(arg0, argv) < 0) {
                PLOG(FATAL) << "Cannot launch snapuserd; execv failed";
            }
            _exit(127);
        }
    }

    auto client = SnapuserdClient::Connect(android::snapshot::kSnapuserdSocket, 10s);
    if (!client) {
        LOG(FATAL) << "Could not connect to first-stage snapuserd";
    }
    if (client->SupportsSecondStageSocketHandoff()) {
        setenv(kSnapuserdFirstStageInfoVar, "socket", 1);
    }

    setenv(kSnapuserdFirstStagePidVar, std::to_string(pid).c_str(), 1);

    if (!client->RemoveTransitionedDaemonIndicator()) {
        LOG(ERROR) << "RemoveTransitionedDaemonIndicator failed";
    }

    LOG(INFO) << "Relaunched snapuserd with pid: " << pid;
}

std::optional<pid_t> GetSnapuserdFirstStagePid() {
    const char* pid_str = getenv(kSnapuserdFirstStagePidVar);
    if (!pid_str) {
        return {};
    }

    int pid = 0;
    if (!android::base::ParseInt(pid_str, &pid)) {
        LOG(FATAL) << "Could not parse pid in environment, " << kSnapuserdFirstStagePidVar << "="
                   << pid_str;
    }
    return {pid};
}

static void RelabelLink(const std::string& link) {
    selinux_android_restorecon(link.c_str(), 0);

    std::string path;
    if (android::base::Readlink(link, &path)) {
        selinux_android_restorecon(path.c_str(), 0);
    }
}

static void RelabelDeviceMapper() {
    selinux_android_restorecon("/dev/device-mapper", 0);

    std::error_code ec;
    for (auto& iter : std::filesystem::directory_iterator("/dev/block", ec)) {
        const auto& path = iter.path();
        if (android::base::StartsWith(path.string(), "/dev/block/dm-")) {
            selinux_android_restorecon(path.string().c_str(), 0);
        }
    }
}

static std::optional<int> GetRamdiskSnapuserdFd() {
    const char* fd_str = getenv(kSnapuserdFirstStageFdVar);
    if (!fd_str) {
        return {};
    }

    int fd;
    if (!android::base::ParseInt(fd_str, &fd)) {
        LOG(FATAL) << "Could not parse fd in environment, " << kSnapuserdFirstStageFdVar << "="
                   << fd_str;
    }
    return {fd};
}

void RestoreconRamdiskSnapuserd(int fd) {
    if (fsetxattr(fd, XATTR_NAME_SELINUX, kSnapuserdLabel, strlen(kSnapuserdLabel) + 1, 0) < 0) {
        PLOG(FATAL) << "fsetxattr snapuserd failed";
    }
}

SnapuserdSelinuxHelper::SnapuserdSelinuxHelper(std::unique_ptr<SnapshotManager>&& sm, pid_t old_pid)
    : sm_(std::move(sm)), old_pid_(old_pid) {
    // Only dm-user device names change during transitions, so the other
    // devices are expected to be present.
    sm_->SetUeventRegenCallback([this](const std::string& device) -> bool {
        if (android::base::StartsWith(device, "/dev/dm-user/")) {
            return block_dev_init_.InitDmUser(android::base::Basename(device));
        }
        return true;
    });
}

static void LockAllSystemPages() {
    bool ok = true;
    auto callback = [&](const android::procinfo::MapInfo& map) -> void {
        if (!ok || android::base::StartsWith(map.name, "/dev/") ||
            !android::base::StartsWith(map.name, "/")) {
            return;
        }
        auto start = reinterpret_cast<const void*>(map.start);
        auto len = map.end - map.start;
        if (!len) {
            return;
        }
        if (mlock(start, len) < 0) {
            LOG(ERROR) << "mlock failed, " << start << " for " << len << " bytes.";
            ok = false;
        }
    };

    if (!android::procinfo::ReadProcessMaps(getpid(), callback) || !ok) {
        LOG(FATAL) << "Could not process /proc/" << getpid() << "/maps file for init, "
                   << "falling back to mlockall().";
        if (mlockall(MCL_CURRENT) < 0) {
            LOG(FATAL) << "mlockall failed";
        }
    }
}

void SnapuserdSelinuxHelper::StartTransition() {
    LOG(INFO) << "Starting SELinux transition of snapuserd";

    // The restorecon path reads from /system etc, so make sure any reads have
    // been cached before proceeding.
    auto handle = selinux_android_file_context_handle();
    if (!handle) {
        LOG(FATAL) << "Could not create SELinux file context handle";
    }
    selinux_android_set_sehandle(handle);

    // We cannot access /system after the transition, so make sure init is
    // pinned in memory.
    LockAllSystemPages();

    argv_.emplace_back("snapuserd");
    argv_.emplace_back("-no_socket");
    if (!sm_->PrepareSnapuserdArgsForSelinux(&argv_)) {
        LOG(FATAL) << "Could not perform selinux transition";
    }
}

void SnapuserdSelinuxHelper::FinishTransition() {
    RelabelLink("/dev/block/by-name/super");
    RelabelDeviceMapper();

    selinux_android_restorecon("/dev/null", 0);
    selinux_android_restorecon("/dev/urandom", 0);
    selinux_android_restorecon("/dev/kmsg", 0);
    selinux_android_restorecon("/dev/dm-user", SELINUX_ANDROID_RESTORECON_RECURSE);

    RelaunchFirstStageSnapuserd();

    if (munlockall() < 0) {
        PLOG(ERROR) << "munlockall failed";
    }
}

/*
 * Before starting init second stage, we will wait
 * for snapuserd daemon to be up and running; bionic libc
 * may read /system/etc/selinux/plat_property_contexts file
 * before invoking main() function. This will happen if
 * init initializes property during second stage. Any access
 * to /system without snapuserd daemon will lead to a deadlock.
 *
 * Thus, we do a simple probe by reading system partition. This
 * read will eventually be serviced by daemon confirming that
 * daemon is up and running. Furthermore, we are still in the kernel
 * domain and sepolicy has not been enforced yet. Thus, access
 * to these device mapper block devices are ok even though
 * we may see audit logs.
 */
bool SnapuserdSelinuxHelper::TestSnapuserdIsReady() {
    // Wait for the daemon to be fully up. Daemon will write to path
    // /metadata/ota/daemon-alive-indicator only when all the threads
    // are ready and attached to dm-user.
    //
    // This check will fail for GRF devices with vendor on Android S.
    // snapuserd binary from Android S won't be able to communicate
    // and hence, we will fallback and issue I/O to verify
    // the presence of daemon.
    auto client = std::make_unique<SnapuserdClient>();
    if (!client->IsTransitionedDaemonReady()) {
        LOG(ERROR) << "IsTransitionedDaemonReady failed";
    }

    std::string dev = "/dev/block/mapper/system"s + fs_mgr_get_slot_suffix();
    android::base::unique_fd fd(open(dev.c_str(), O_RDONLY | O_DIRECT));
    if (fd < 0) {
        PLOG(ERROR) << "open " << dev << " failed";
        return false;
    }

    void* addr;
    ssize_t page_size = getpagesize();
    if (posix_memalign(&addr, page_size, page_size) < 0) {
        PLOG(ERROR) << "posix_memalign with page size " << page_size;
        return false;
    }

    std::unique_ptr<void, decltype(&::free)> buffer(addr, ::free);

    int iter = 0;
    while (iter < 10) {
        ssize_t n = TEMP_FAILURE_RETRY(pread(fd.get(), buffer.get(), page_size, 0));
        if (n < 0) {
            // Wait for sometime before retry
            std::this_thread::sleep_for(100ms);
        } else if (n == page_size) {
            return true;
        } else {
            LOG(ERROR) << "pread returned: " << n << " from: " << dev << " expected: " << page_size;
        }

        iter += 1;
    }

    return false;
}

void SnapuserdSelinuxHelper::RelaunchFirstStageSnapuserd() {
    if (!sm_->DetachFirstStageSnapuserdForSelinux()) {
        LOG(FATAL) << "Could not perform selinux transition";
    }

    KillFirstStageSnapuserd(old_pid_);

    auto fd = GetRamdiskSnapuserdFd();
    if (!fd) {
        LOG(FATAL) << "Environment variable " << kSnapuserdFirstStageFdVar << " was not set!";
    }
    unsetenv(kSnapuserdFirstStageFdVar);

    RestoreconRamdiskSnapuserd(fd.value());

    pid_t pid = fork();
    if (pid < 0) {
        PLOG(FATAL) << "Fork to relaunch snapuserd failed";
    }
    if (pid > 0) {
        // We don't need the descriptor anymore, and it should be closed to
        // avoid leaking into subprocesses.
        close(fd.value());

        setenv(kSnapuserdFirstStagePidVar, std::to_string(pid).c_str(), 1);

        LOG(INFO) << "Relaunched snapuserd with pid: " << pid;

        // Since daemon is not started as a service, we have
        // to explicitly set the OOM score to default which is unkillable
        std::string oom_str = std::to_string(DEFAULT_OOM_SCORE_ADJUST);
        std::string oom_file = android::base::StringPrintf("/proc/%d/oom_score_adj", pid);
        if (!android::base::WriteStringToFile(oom_str, oom_file)) {
            PLOG(ERROR) << "couldn't write oom_score_adj to snapuserd daemon with pid: " << pid;
        }

        if (!TestSnapuserdIsReady()) {
            PLOG(FATAL) << "snapuserd daemon failed to launch";
        } else {
            LOG(INFO) << "snapuserd daemon is up and running";
        }

        return;
    }

    // Make sure the descriptor is gone after we exec.
    if (fcntl(fd.value(), F_SETFD, FD_CLOEXEC) < 0) {
        PLOG(FATAL) << "fcntl FD_CLOEXEC failed for snapuserd fd";
    }

    std::vector<char*> argv;
    for (auto& arg : argv_) {
        argv.emplace_back(arg.data());
    }
    argv.emplace_back(nullptr);

    int rv = syscall(SYS_execveat, fd.value(), "", reinterpret_cast<char* const*>(argv.data()),
                     nullptr, AT_EMPTY_PATH);
    if (rv < 0) {
        PLOG(FATAL) << "Failed to execveat() snapuserd";
    }
}

std::unique_ptr<SnapuserdSelinuxHelper> SnapuserdSelinuxHelper::CreateIfNeeded() {
    if (IsRecoveryMode()) {
        return nullptr;
    }

    auto old_pid = GetSnapuserdFirstStagePid();
    if (!old_pid) {
        return nullptr;
    }

    auto sm = SnapshotManager::NewForFirstStageMount();
    if (!sm) {
        LOG(FATAL) << "Unable to create SnapshotManager";
    }
    return std::make_unique<SnapuserdSelinuxHelper>(std::move(sm), old_pid.value());
}

void KillFirstStageSnapuserd(pid_t pid) {
    if (kill(pid, SIGTERM) < 0 && errno != ESRCH) {
        LOG(ERROR) << "Kill snapuserd pid failed: " << pid;
    } else {
        LOG(INFO) << "Sent SIGTERM to snapuserd process " << pid;
    }
}

void CleanupSnapuserdSocket() {
    auto socket_path = ANDROID_SOCKET_DIR "/"s + android::snapshot::kSnapuserdSocket;
    if (access(socket_path.c_str(), F_OK) != 0) {
        return;
    }

    // Tell the daemon to stop accepting connections and to gracefully exit
    // once all outstanding handlers have terminated.
    if (auto client = SnapuserdClient::Connect(android::snapshot::kSnapuserdSocket, 3s)) {
        client->DetachSnapuserd();
    }

    // Unlink the socket so we can create it again in second-stage.
    if (unlink(socket_path.c_str()) < 0) {
        PLOG(FATAL) << "unlink " << socket_path << " failed";
    }
}

void SaveRamdiskPathToSnapuserd() {
    int fd = open(kSnapuserdPath, O_PATH);
    if (fd < 0) {
        PLOG(FATAL) << "Unable to open snapuserd: " << kSnapuserdPath;
    }

    auto value = std::to_string(fd);
    if (setenv(kSnapuserdFirstStageFdVar, value.c_str(), 1) < 0) {
        PLOG(FATAL) << "setenv failed: " << kSnapuserdFirstStageFdVar << "=" << value;
    }
}

bool IsFirstStageSnapuserdRunning() {
    return GetSnapuserdFirstStagePid().has_value();
}

std::vector<std::string> GetSnapuserdFirstStageInfo() {
    const char* pid_str = getenv(kSnapuserdFirstStageInfoVar);
    if (!pid_str) {
        return {};
    }
    return android::base::Split(pid_str, ",");
}

}  // namespace init
}  // namespace android

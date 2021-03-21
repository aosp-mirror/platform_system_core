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

// This file contains the functions that initialize SELinux during boot as well as helper functions
// for SELinux operation for init.

// When the system boots, there is no SEPolicy present and init is running in the kernel domain.
// Init loads the SEPolicy from the file system, restores the context of /system/bin/init based on
// this SEPolicy, and finally exec()'s itself to run in the proper domain.

// The SEPolicy on Android comes in two variants: monolithic and split.

// The monolithic policy variant is for legacy non-treble devices that contain a single SEPolicy
// file located at /sepolicy and is directly loaded into the kernel SELinux subsystem.

// The split policy is for supporting treble devices.  It splits the SEPolicy across files on
// /system/etc/selinux (the 'plat' portion of the policy) and /vendor/etc/selinux (the 'nonplat'
// portion of the policy).  This is necessary to allow the system image to be updated independently
// of the vendor image, while maintaining contributions from both partitions in the SEPolicy.  This
// is especially important for VTS testing, where the SEPolicy on the Google System Image may not be
// identical to the system image shipped on a vendor's device.

// The split SEPolicy is loaded as described below:
// 1) There is a precompiled SEPolicy located at either /vendor/etc/selinux/precompiled_sepolicy or
//    /odm/etc/selinux/precompiled_sepolicy if odm parition is present.  Stored along with this file
//    are the sha256 hashes of the parts of the SEPolicy on /system, /system_ext and /product that
//    were used to compile this precompiled policy.  The system partition contains a similar sha256
//    of the parts of the SEPolicy that it currently contains.  Symmetrically, system_ext and
//    product paritition contain sha256 hashes of their SEPolicy.  The init loads this
//    precompiled_sepolicy directly if and only if the hashes along with the precompiled SEPolicy on
//    /vendor or /odm match the hashes for system, system_ext and product SEPolicy, respectively.
// 2) If these hashes do not match, then either /system or /system_ext or /product (or some of them)
//    have been updated out of sync with /vendor (or /odm if it is present) and the init needs to
//    compile the SEPolicy.  /system contains the SEPolicy compiler, secilc, and it is used by the
//    OpenSplitPolicy() function below to compile the SEPolicy to a temp directory and load it.
//    That function contains even more documentation with the specific implementation details of how
//    the SEPolicy is compiled if needed.

#include "selinux.h"

#include <android/api-level.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/netlink.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#include <android-base/chrono_utils.h>
#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/result.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <fs_avb/fs_avb.h>
#include <fs_mgr.h>
#include <libgsi/libgsi.h>
#include <libsnapshot/snapshot.h>
#include <selinux/android.h>

#include "block_dev_initializer.h"
#include "debug_ramdisk.h"
#include "reboot_utils.h"
#include "snapuserd_transition.h"
#include "util.h"

using namespace std::string_literals;

using android::base::ParseInt;
using android::base::Timer;
using android::base::unique_fd;
using android::fs_mgr::AvbHandle;
using android::snapshot::SnapshotManager;

namespace android {
namespace init {

namespace {

enum EnforcingStatus { SELINUX_PERMISSIVE, SELINUX_ENFORCING };

EnforcingStatus StatusFromProperty() {
    EnforcingStatus status = SELINUX_ENFORCING;

    ImportKernelCmdline([&](const std::string& key, const std::string& value) {
        if (key == "androidboot.selinux" && value == "permissive") {
            status = SELINUX_PERMISSIVE;
        }
    });

    if (status == SELINUX_ENFORCING) {
        ImportBootconfig([&](const std::string& key, const std::string& value) {
            if (key == "androidboot.selinux" && value == "permissive") {
                status = SELINUX_PERMISSIVE;
            }
        });
    }

    return status;
}

bool IsEnforcing() {
    if (ALLOW_PERMISSIVE_SELINUX) {
        return StatusFromProperty() == SELINUX_ENFORCING;
    }
    return true;
}

// Forks, executes the provided program in the child, and waits for the completion in the parent.
// Child's stderr is captured and logged using LOG(ERROR).
bool ForkExecveAndWaitForCompletion(const char* filename, char* const argv[]) {
    // Create a pipe used for redirecting child process's output.
    // * pipe_fds[0] is the FD the parent will use for reading.
    // * pipe_fds[1] is the FD the child will use for writing.
    int pipe_fds[2];
    if (pipe(pipe_fds) == -1) {
        PLOG(ERROR) << "Failed to create pipe";
        return false;
    }

    pid_t child_pid = fork();
    if (child_pid == -1) {
        PLOG(ERROR) << "Failed to fork for " << filename;
        return false;
    }

    if (child_pid == 0) {
        // fork succeeded -- this is executing in the child process

        // Close the pipe FD not used by this process
        close(pipe_fds[0]);

        // Redirect stderr to the pipe FD provided by the parent
        if (TEMP_FAILURE_RETRY(dup2(pipe_fds[1], STDERR_FILENO)) == -1) {
            PLOG(ERROR) << "Failed to redirect stderr of " << filename;
            _exit(127);
            return false;
        }
        close(pipe_fds[1]);

        if (execv(filename, argv) == -1) {
            PLOG(ERROR) << "Failed to execve " << filename;
            return false;
        }
        // Unreachable because execve will have succeeded and replaced this code
        // with child process's code.
        _exit(127);
        return false;
    } else {
        // fork succeeded -- this is executing in the original/parent process

        // Close the pipe FD not used by this process
        close(pipe_fds[1]);

        // Log the redirected output of the child process.
        // It's unfortunate that there's no standard way to obtain an istream for a file descriptor.
        // As a result, we're buffering all output and logging it in one go at the end of the
        // invocation, instead of logging it as it comes in.
        const int child_out_fd = pipe_fds[0];
        std::string child_output;
        if (!android::base::ReadFdToString(child_out_fd, &child_output)) {
            PLOG(ERROR) << "Failed to capture full output of " << filename;
        }
        close(child_out_fd);
        if (!child_output.empty()) {
            // Log captured output, line by line, because LOG expects to be invoked for each line
            std::istringstream in(child_output);
            std::string line;
            while (std::getline(in, line)) {
                LOG(ERROR) << filename << ": " << line;
            }
        }

        // Wait for child to terminate
        int status;
        if (TEMP_FAILURE_RETRY(waitpid(child_pid, &status, 0)) != child_pid) {
            PLOG(ERROR) << "Failed to wait for " << filename;
            return false;
        }

        if (WIFEXITED(status)) {
            int status_code = WEXITSTATUS(status);
            if (status_code == 0) {
                return true;
            } else {
                LOG(ERROR) << filename << " exited with status " << status_code;
            }
        } else if (WIFSIGNALED(status)) {
            LOG(ERROR) << filename << " killed by signal " << WTERMSIG(status);
        } else if (WIFSTOPPED(status)) {
            LOG(ERROR) << filename << " stopped by signal " << WSTOPSIG(status);
        } else {
            LOG(ERROR) << "waitpid for " << filename << " returned unexpected status: " << status;
        }

        return false;
    }
}

bool ReadFirstLine(const char* file, std::string* line) {
    line->clear();

    std::string contents;
    if (!android::base::ReadFileToString(file, &contents, true /* follow symlinks */)) {
        return false;
    }
    std::istringstream in(contents);
    std::getline(in, *line);
    return true;
}

Result<std::string> FindPrecompiledSplitPolicy() {
    std::string precompiled_sepolicy;
    // If there is an odm partition, precompiled_sepolicy will be in
    // odm/etc/selinux. Otherwise it will be in vendor/etc/selinux.
    static constexpr const char vendor_precompiled_sepolicy[] =
        "/vendor/etc/selinux/precompiled_sepolicy";
    static constexpr const char odm_precompiled_sepolicy[] =
        "/odm/etc/selinux/precompiled_sepolicy";
    if (access(odm_precompiled_sepolicy, R_OK) == 0) {
        precompiled_sepolicy = odm_precompiled_sepolicy;
    } else if (access(vendor_precompiled_sepolicy, R_OK) == 0) {
        precompiled_sepolicy = vendor_precompiled_sepolicy;
    } else {
        return ErrnoError() << "No precompiled sepolicy at " << vendor_precompiled_sepolicy;
    }

    // Use precompiled sepolicy only when all corresponding hashes are equal.
    // plat_sepolicy is always checked, while system_ext and product are checked only when they
    // exist.
    std::vector<std::pair<std::string, std::string>> sepolicy_hashes{
            {"/system/etc/selinux/plat_sepolicy_and_mapping.sha256",
             precompiled_sepolicy + ".plat_sepolicy_and_mapping.sha256"},
    };

    if (access("/system_ext/etc/selinux/system_ext_sepolicy.cil", F_OK) == 0) {
        sepolicy_hashes.emplace_back(
                "/system_ext/etc/selinux/system_ext_sepolicy_and_mapping.sha256",
                precompiled_sepolicy + ".system_ext_sepolicy_and_mapping.sha256");
    }

    if (access("/product/etc/selinux/product_sepolicy.cil", F_OK) == 0) {
        sepolicy_hashes.emplace_back("/product/etc/selinux/product_sepolicy_and_mapping.sha256",
                                     precompiled_sepolicy + ".product_sepolicy_and_mapping.sha256");
    }

    for (const auto& [actual_id_path, precompiled_id_path] : sepolicy_hashes) {
        std::string actual_id;
        if (!ReadFirstLine(actual_id_path.c_str(), &actual_id)) {
            return ErrnoError() << "Failed to read " << actual_id_path;
        }

        std::string precompiled_id;
        if (!ReadFirstLine(precompiled_id_path.c_str(), &precompiled_id)) {
            return ErrnoError() << "Failed to read " << precompiled_id_path;
        }

        if (actual_id.empty() || actual_id != precompiled_id) {
            return Error() << actual_id_path << " and " << precompiled_id_path << " differ";
        }
    }

    return precompiled_sepolicy;
}

bool GetVendorMappingVersion(std::string* plat_vers) {
    if (!ReadFirstLine("/vendor/etc/selinux/plat_sepolicy_vers.txt", plat_vers)) {
        PLOG(ERROR) << "Failed to read /vendor/etc/selinux/plat_sepolicy_vers.txt";
        return false;
    }
    if (plat_vers->empty()) {
        LOG(ERROR) << "No version present in plat_sepolicy_vers.txt";
        return false;
    }
    return true;
}

constexpr const char plat_policy_cil_file[] = "/system/etc/selinux/plat_sepolicy.cil";

bool IsSplitPolicyDevice() {
    return access(plat_policy_cil_file, R_OK) != -1;
}

struct PolicyFile {
    unique_fd fd;
    std::string path;
};

bool OpenSplitPolicy(PolicyFile* policy_file) {
    // IMPLEMENTATION NOTE: Split policy consists of three CIL files:
    // * platform -- policy needed due to logic contained in the system image,
    // * non-platform -- policy needed due to logic contained in the vendor image,
    // * mapping -- mapping policy which helps preserve forward-compatibility of non-platform policy
    //   with newer versions of platform policy.
    //
    // secilc is invoked to compile the above three policy files into a single monolithic policy
    // file. This file is then loaded into the kernel.

    // See if we need to load userdebug_plat_sepolicy.cil instead of plat_sepolicy.cil.
    const char* force_debuggable_env = getenv("INIT_FORCE_DEBUGGABLE");
    bool use_userdebug_policy =
            ((force_debuggable_env && "true"s == force_debuggable_env) &&
             AvbHandle::IsDeviceUnlocked() && access(kDebugRamdiskSEPolicy, F_OK) == 0);
    if (use_userdebug_policy) {
        LOG(WARNING) << "Using userdebug system sepolicy";
    }

    // Load precompiled policy from vendor image, if a matching policy is found there. The policy
    // must match the platform policy on the system image.
    // use_userdebug_policy requires compiling sepolicy with userdebug_plat_sepolicy.cil.
    // Thus it cannot use the precompiled policy from vendor image.
    if (!use_userdebug_policy) {
        if (auto res = FindPrecompiledSplitPolicy(); res.ok()) {
            unique_fd fd(open(res->c_str(), O_RDONLY | O_CLOEXEC | O_BINARY));
            if (fd != -1) {
                policy_file->fd = std::move(fd);
                policy_file->path = std::move(*res);
                return true;
            }
        } else {
            LOG(INFO) << res.error();
        }
    }
    // No suitable precompiled policy could be loaded

    LOG(INFO) << "Compiling SELinux policy";

    // We store the output of the compilation on /dev because this is the most convenient tmpfs
    // storage mount available this early in the boot sequence.
    char compiled_sepolicy[] = "/dev/sepolicy.XXXXXX";
    unique_fd compiled_sepolicy_fd(mkostemp(compiled_sepolicy, O_CLOEXEC));
    if (compiled_sepolicy_fd < 0) {
        PLOG(ERROR) << "Failed to create temporary file " << compiled_sepolicy;
        return false;
    }

    // Determine which mapping file to include
    std::string vend_plat_vers;
    if (!GetVendorMappingVersion(&vend_plat_vers)) {
        return false;
    }
    std::string plat_mapping_file("/system/etc/selinux/mapping/" + vend_plat_vers + ".cil");

    std::string plat_compat_cil_file("/system/etc/selinux/mapping/" + vend_plat_vers +
                                     ".compat.cil");
    if (access(plat_compat_cil_file.c_str(), F_OK) == -1) {
        plat_compat_cil_file.clear();
    }

    std::string system_ext_policy_cil_file("/system_ext/etc/selinux/system_ext_sepolicy.cil");
    if (access(system_ext_policy_cil_file.c_str(), F_OK) == -1) {
        system_ext_policy_cil_file.clear();
    }

    std::string system_ext_mapping_file("/system_ext/etc/selinux/mapping/" + vend_plat_vers +
                                        ".cil");
    if (access(system_ext_mapping_file.c_str(), F_OK) == -1) {
        system_ext_mapping_file.clear();
    }

    std::string product_policy_cil_file("/product/etc/selinux/product_sepolicy.cil");
    if (access(product_policy_cil_file.c_str(), F_OK) == -1) {
        product_policy_cil_file.clear();
    }

    std::string product_mapping_file("/product/etc/selinux/mapping/" + vend_plat_vers + ".cil");
    if (access(product_mapping_file.c_str(), F_OK) == -1) {
        product_mapping_file.clear();
    }

    // vendor_sepolicy.cil and plat_pub_versioned.cil are the new design to replace
    // nonplat_sepolicy.cil.
    std::string plat_pub_versioned_cil_file("/vendor/etc/selinux/plat_pub_versioned.cil");
    std::string vendor_policy_cil_file("/vendor/etc/selinux/vendor_sepolicy.cil");

    if (access(vendor_policy_cil_file.c_str(), F_OK) == -1) {
        // For backward compatibility.
        // TODO: remove this after no device is using nonplat_sepolicy.cil.
        vendor_policy_cil_file = "/vendor/etc/selinux/nonplat_sepolicy.cil";
        plat_pub_versioned_cil_file.clear();
    } else if (access(plat_pub_versioned_cil_file.c_str(), F_OK) == -1) {
        LOG(ERROR) << "Missing " << plat_pub_versioned_cil_file;
        return false;
    }

    // odm_sepolicy.cil is default but optional.
    std::string odm_policy_cil_file("/odm/etc/selinux/odm_sepolicy.cil");
    if (access(odm_policy_cil_file.c_str(), F_OK) == -1) {
        odm_policy_cil_file.clear();
    }
    const std::string version_as_string = std::to_string(SEPOLICY_VERSION);

    // clang-format off
    std::vector<const char*> compile_args {
        "/system/bin/secilc",
        use_userdebug_policy ? kDebugRamdiskSEPolicy: plat_policy_cil_file,
        "-m", "-M", "true", "-G", "-N",
        "-c", version_as_string.c_str(),
        plat_mapping_file.c_str(),
        "-o", compiled_sepolicy,
        // We don't care about file_contexts output by the compiler
        "-f", "/sys/fs/selinux/null",  // /dev/null is not yet available
    };
    // clang-format on

    if (!plat_compat_cil_file.empty()) {
        compile_args.push_back(plat_compat_cil_file.c_str());
    }
    if (!system_ext_policy_cil_file.empty()) {
        compile_args.push_back(system_ext_policy_cil_file.c_str());
    }
    if (!system_ext_mapping_file.empty()) {
        compile_args.push_back(system_ext_mapping_file.c_str());
    }
    if (!product_policy_cil_file.empty()) {
        compile_args.push_back(product_policy_cil_file.c_str());
    }
    if (!product_mapping_file.empty()) {
        compile_args.push_back(product_mapping_file.c_str());
    }
    if (!plat_pub_versioned_cil_file.empty()) {
        compile_args.push_back(plat_pub_versioned_cil_file.c_str());
    }
    if (!vendor_policy_cil_file.empty()) {
        compile_args.push_back(vendor_policy_cil_file.c_str());
    }
    if (!odm_policy_cil_file.empty()) {
        compile_args.push_back(odm_policy_cil_file.c_str());
    }
    compile_args.push_back(nullptr);

    if (!ForkExecveAndWaitForCompletion(compile_args[0], (char**)compile_args.data())) {
        unlink(compiled_sepolicy);
        return false;
    }
    unlink(compiled_sepolicy);

    policy_file->fd = std::move(compiled_sepolicy_fd);
    policy_file->path = compiled_sepolicy;
    return true;
}

bool OpenMonolithicPolicy(PolicyFile* policy_file) {
    static constexpr char kSepolicyFile[] = "/sepolicy";

    LOG(VERBOSE) << "Opening SELinux policy from monolithic file";
    policy_file->fd.reset(open(kSepolicyFile, O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
    if (policy_file->fd < 0) {
        PLOG(ERROR) << "Failed to open monolithic SELinux policy";
        return false;
    }
    policy_file->path = kSepolicyFile;
    return true;
}

void ReadPolicy(std::string* policy) {
    PolicyFile policy_file;

    bool ok = IsSplitPolicyDevice() ? OpenSplitPolicy(&policy_file)
                                    : OpenMonolithicPolicy(&policy_file);
    if (!ok) {
        LOG(FATAL) << "Unable to open SELinux policy";
    }

    if (!android::base::ReadFdToString(policy_file.fd, policy)) {
        PLOG(FATAL) << "Failed to read policy file: " << policy_file.path;
    }
}

void SelinuxSetEnforcement() {
    bool kernel_enforcing = (security_getenforce() == 1);
    bool is_enforcing = IsEnforcing();
    if (kernel_enforcing != is_enforcing) {
        if (security_setenforce(is_enforcing)) {
            PLOG(FATAL) << "security_setenforce(" << (is_enforcing ? "true" : "false")
                        << ") failed";
        }
    }

    if (auto result = WriteFile("/sys/fs/selinux/checkreqprot", "0"); !result.ok()) {
        LOG(FATAL) << "Unable to write to /sys/fs/selinux/checkreqprot: " << result.error();
    }
}

constexpr size_t kKlogMessageSize = 1024;

void SelinuxAvcLog(char* buf, size_t buf_len) {
    CHECK_GT(buf_len, 0u);

    size_t str_len = strnlen(buf, buf_len);
    // trim newline at end of string
    if (buf[str_len - 1] == '\n') {
        buf[str_len - 1] = '\0';
    }

    struct NetlinkMessage {
        nlmsghdr hdr;
        char buf[kKlogMessageSize];
    } request = {};

    request.hdr.nlmsg_flags = NLM_F_REQUEST;
    request.hdr.nlmsg_type = AUDIT_USER_AVC;
    request.hdr.nlmsg_len = sizeof(request);
    strlcpy(request.buf, buf, sizeof(request.buf));

    auto fd = unique_fd{socket(PF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_AUDIT)};
    if (!fd.ok()) {
        return;
    }

    TEMP_FAILURE_RETRY(send(fd, &request, sizeof(request), 0));
}

}  // namespace

void SelinuxRestoreContext() {
    LOG(INFO) << "Running restorecon...";
    selinux_android_restorecon("/dev", 0);
    selinux_android_restorecon("/dev/kmsg", 0);
    if constexpr (WORLD_WRITABLE_KMSG) {
        selinux_android_restorecon("/dev/kmsg_debug", 0);
    }
    selinux_android_restorecon("/dev/null", 0);
    selinux_android_restorecon("/dev/ptmx", 0);
    selinux_android_restorecon("/dev/socket", 0);
    selinux_android_restorecon("/dev/random", 0);
    selinux_android_restorecon("/dev/urandom", 0);
    selinux_android_restorecon("/dev/__properties__", 0);

    selinux_android_restorecon("/dev/block", SELINUX_ANDROID_RESTORECON_RECURSE);
    selinux_android_restorecon("/dev/dm-user", SELINUX_ANDROID_RESTORECON_RECURSE);
    selinux_android_restorecon("/dev/device-mapper", 0);

    selinux_android_restorecon("/apex", 0);

    selinux_android_restorecon("/linkerconfig", 0);

    // adb remount, snapshot-based updates, and DSUs all create files during
    // first-stage init.
    selinux_android_restorecon(SnapshotManager::GetGlobalRollbackIndicatorPath().c_str(), 0);
    selinux_android_restorecon("/metadata/gsi", SELINUX_ANDROID_RESTORECON_RECURSE |
                                                        SELINUX_ANDROID_RESTORECON_SKIP_SEHASH);
}

int SelinuxKlogCallback(int type, const char* fmt, ...) {
    android::base::LogSeverity severity = android::base::ERROR;
    if (type == SELINUX_WARNING) {
        severity = android::base::WARNING;
    } else if (type == SELINUX_INFO) {
        severity = android::base::INFO;
    }
    char buf[kKlogMessageSize];
    va_list ap;
    va_start(ap, fmt);
    int length_written = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (length_written <= 0) {
        return 0;
    }
    if (type == SELINUX_AVC) {
        SelinuxAvcLog(buf, sizeof(buf));
    } else {
        android::base::KernelLogger(android::base::MAIN, severity, "selinux", nullptr, 0, buf);
    }
    return 0;
}

void SelinuxSetupKernelLogging() {
    selinux_callback cb;
    cb.func_log = SelinuxKlogCallback;
    selinux_set_callback(SELINUX_CB_LOG, cb);
}

int SelinuxGetVendorAndroidVersion() {
    static int vendor_android_version = [] {
        if (!IsSplitPolicyDevice()) {
            // If this device does not split sepolicy files, it's not a Treble device and therefore,
            // we assume it's always on the latest platform.
            return __ANDROID_API_FUTURE__;
        }

        std::string version;
        if (!GetVendorMappingVersion(&version)) {
            LOG(FATAL) << "Could not read vendor SELinux version";
        }

        int major_version;
        std::string major_version_str(version, 0, version.find('.'));
        if (!ParseInt(major_version_str, &major_version)) {
            PLOG(FATAL) << "Failed to parse the vendor sepolicy major version "
                        << major_version_str;
        }

        return major_version;
    }();
    return vendor_android_version;
}

// This is for R system.img/system_ext.img to work on old vendor.img as system_ext.img
// is introduced in R. We mount system_ext in second stage init because the first-stage
// init in boot.img won't be updated in the system-only OTA scenario.
void MountMissingSystemPartitions() {
    android::fs_mgr::Fstab fstab;
    if (!ReadDefaultFstab(&fstab)) {
        LOG(ERROR) << "Could not read default fstab";
    }

    android::fs_mgr::Fstab mounts;
    if (!ReadFstabFromFile("/proc/mounts", &mounts)) {
        LOG(ERROR) << "Could not read /proc/mounts";
    }

    static const std::vector<std::string> kPartitionNames = {"system_ext", "product"};

    android::fs_mgr::Fstab extra_fstab;
    for (const auto& name : kPartitionNames) {
        if (GetEntryForMountPoint(&mounts, "/"s + name)) {
            // The partition is already mounted.
            continue;
        }

        auto system_entry = GetEntryForMountPoint(&fstab, "/system");
        if (!system_entry) {
            LOG(ERROR) << "Could not find mount entry for /system";
            break;
        }
        if (!system_entry->fs_mgr_flags.logical) {
            LOG(INFO) << "Skipping mount of " << name << ", system is not dynamic.";
            break;
        }

        auto entry = *system_entry;
        auto partition_name = name + fs_mgr_get_slot_suffix();
        auto replace_name = "system"s + fs_mgr_get_slot_suffix();

        entry.mount_point = "/"s + name;
        entry.blk_device =
                android::base::StringReplace(entry.blk_device, replace_name, partition_name, false);
        if (!fs_mgr_update_logical_partition(&entry)) {
            LOG(ERROR) << "Could not update logical partition";
            continue;
        }

        extra_fstab.emplace_back(std::move(entry));
    }

    SkipMountingPartitions(&extra_fstab);
    if (extra_fstab.empty()) {
        return;
    }

    BlockDevInitializer block_dev_init;
    for (auto& entry : extra_fstab) {
        if (access(entry.blk_device.c_str(), F_OK) != 0) {
            auto block_dev = android::base::Basename(entry.blk_device);
            if (!block_dev_init.InitDmDevice(block_dev)) {
                LOG(ERROR) << "Failed to find device-mapper node: " << block_dev;
                continue;
            }
        }
        if (fs_mgr_do_mount_one(entry)) {
            LOG(ERROR) << "Could not mount " << entry.mount_point;
        }
    }
}

static void LoadSelinuxPolicy(std::string& policy) {
    LOG(INFO) << "Loading SELinux policy";

    set_selinuxmnt("/sys/fs/selinux");
    if (security_load_policy(policy.data(), policy.size()) < 0) {
        PLOG(FATAL) << "SELinux:  Could not load policy";
    }
}

// The SELinux setup process is carefully orchestrated around snapuserd. Policy
// must be loaded off dynamic partitions, and during an OTA, those partitions
// cannot be read without snapuserd. But, with kernel-privileged snapuserd
// running, loading the policy will immediately trigger audits.
//
// We use a five-step process to address this:
//  (1) Read the policy into a string, with snapuserd running.
//  (2) Rewrite the snapshot device-mapper tables, to generate new dm-user
//      devices and to flush I/O.
//  (3) Kill snapuserd, which no longer has any dm-user devices to attach to.
//  (4) Load the sepolicy and issue critical restorecons in /dev, carefully
//      avoiding anything that would read from /system.
//  (5) Re-launch snapuserd and attach it to the dm-user devices from step (2).
//
// After this sequence, it is safe to enable enforcing mode and continue booting.
int SetupSelinux(char** argv) {
    SetStdioToDevNull(argv);
    InitKernelLogging(argv);

    if (REBOOT_BOOTLOADER_ON_PANIC) {
        InstallRebootSignalHandlers();
    }

    boot_clock::time_point start_time = boot_clock::now();

    MountMissingSystemPartitions();

    SelinuxSetupKernelLogging();

    LOG(INFO) << "Opening SELinux policy";

    // Read the policy before potentially killing snapuserd.
    std::string policy;
    ReadPolicy(&policy);

    auto snapuserd_helper = SnapuserdSelinuxHelper::CreateIfNeeded();
    if (snapuserd_helper) {
        // Kill the old snapused to avoid audit messages. After this we cannot
        // read from /system (or other dynamic partitions) until we call
        // FinishTransition().
        snapuserd_helper->StartTransition();
    }

    LoadSelinuxPolicy(policy);

    if (snapuserd_helper) {
        // Before enforcing, finish the pending snapuserd transition.
        snapuserd_helper->FinishTransition();
        snapuserd_helper = nullptr;
    }

    SelinuxSetEnforcement();

    // We're in the kernel domain and want to transition to the init domain.  File systems that
    // store SELabels in their xattrs, such as ext4 do not need an explicit restorecon here,
    // but other file systems do.  In particular, this is needed for ramdisks such as the
    // recovery image for A/B devices.
    if (selinux_android_restorecon("/system/bin/init", 0) == -1) {
        PLOG(FATAL) << "restorecon failed of /system/bin/init failed";
    }

    setenv(kEnvSelinuxStartedAt, std::to_string(start_time.time_since_epoch().count()).c_str(), 1);

    const char* path = "/system/bin/init";
    const char* args[] = {path, "second_stage", nullptr};
    execv(path, const_cast<char**>(args));

    // execv() only returns if an error happened, in which case we
    // panic and never return from this function.
    PLOG(FATAL) << "execv(\"" << path << "\") failed";

    return 1;
}

}  // namespace init
}  // namespace android

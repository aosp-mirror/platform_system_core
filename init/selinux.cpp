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

// The split policy is for supporting treble devices and updateable apexes.  It splits the SEPolicy
// across files on /system/etc/selinux (the 'plat' portion of the policy), /vendor/etc/selinux
// (the 'vendor' portion of the policy), /system_ext/etc/selinux, /product/etc/selinux,
// /odm/etc/selinux, and /dev/selinux (the apex portion of policy).  This is necessary to allow
// images to be updated independently of the vendor image, while maintaining contributions from
// multiple partitions in the SEPolicy.  This is especially important for VTS testing, where the
// SEPolicy on the Google System Image may not be identical to the system image shipped on a
// vendor's device.

// The split SEPolicy is loaded as described below:
// 1) There is a precompiled SEPolicy located at either /vendor/etc/selinux/precompiled_sepolicy or
//    /odm/etc/selinux/precompiled_sepolicy if odm parition is present.  Stored along with this file
//    are the sha256 hashes of the parts of the SEPolicy on /system, /system_ext, /product, and apex
//    that were used to compile this precompiled policy.  The system partition contains a similar
//    sha256 of the parts of the SEPolicy that it currently contains. Symmetrically, system_ext,
//    product, and apex contain sha256 hashes of their SEPolicy. Init loads this
//    precompiled_sepolicy directly if and only if the hashes along with the precompiled SEPolicy on
//    /vendor or /odm match the hashes for system, system_ext, product, and apex SEPolicy,
//    respectively.
// 2) If these hashes do not match, then either /system or /system_ext /product, or apex (or some of
//    them) have been updated out of sync with /vendor (or /odm if it is present) and the init needs
//    to compile the SEPolicy.  /system contains the SEPolicy compiler, secilc, and it is used by
//    the OpenSplitPolicy() function below to compile the SEPolicy to a temp directory and load it.
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
#include <fstream>

#include <CertUtils.h>
#include <android-base/chrono_utils.h>
#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/result.h>
#include <android-base/scopeguard.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <fs_avb/fs_avb.h>
#include <fs_mgr.h>
#include <fsverity_init.h>
#include <libgsi/libgsi.h>
#include <libsnapshot/snapshot.h>
#include <mini_keyctl_utils.h>
#include <selinux/android.h>
#include <ziparchive/zip_archive.h>

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
    std::vector<std::pair<std::string, std::string>> sepolicy_hashes{
            {"/system/etc/selinux/plat_sepolicy_and_mapping.sha256",
             precompiled_sepolicy + ".plat_sepolicy_and_mapping.sha256"},
            {"/system_ext/etc/selinux/system_ext_sepolicy_and_mapping.sha256",
             precompiled_sepolicy + ".system_ext_sepolicy_and_mapping.sha256"},
            {"/product/etc/selinux/product_sepolicy_and_mapping.sha256",
             precompiled_sepolicy + ".product_sepolicy_and_mapping.sha256"},
            {"/dev/selinux/apex_sepolicy.sha256", precompiled_sepolicy + ".apex_sepolicy.sha256"},
    };

    for (const auto& [actual_id_path, precompiled_id_path] : sepolicy_hashes) {
        // Both of them should exist or both of them shouldn't exist.
        if (access(actual_id_path.c_str(), R_OK) != 0) {
            if (access(precompiled_id_path.c_str(), R_OK) == 0) {
                return Error() << precompiled_id_path << " exists but " << actual_id_path
                               << " doesn't";
            }
            continue;
        }

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

std::optional<const char*> GetUserdebugPlatformPolicyFile() {
    // See if we need to load userdebug_plat_sepolicy.cil instead of plat_sepolicy.cil.
    const char* force_debuggable_env = getenv("INIT_FORCE_DEBUGGABLE");
    if (force_debuggable_env && "true"s == force_debuggable_env && AvbHandle::IsDeviceUnlocked()) {
        const std::vector<const char*> debug_policy_candidates = {
#if INSTALL_DEBUG_POLICY_TO_SYSTEM_EXT == 1
            "/system_ext/etc/selinux/userdebug_plat_sepolicy.cil",
#endif
            kDebugRamdiskSEPolicy,
        };
        for (const char* debug_policy : debug_policy_candidates) {
            if (access(debug_policy, F_OK) == 0) {
                return debug_policy;
            }
        }
    }
    return std::nullopt;
}

struct PolicyFile {
    unique_fd fd;
    std::string path;
};

bool OpenSplitPolicy(PolicyFile* policy_file) {
    // IMPLEMENTATION NOTE: Split policy consists of three or more CIL files:
    // * platform -- policy needed due to logic contained in the system image,
    // * vendor -- policy needed due to logic contained in the vendor image,
    // * mapping -- mapping policy which helps preserve forward-compatibility of non-platform policy
    //   with newer versions of platform policy.
    // * (optional) policy needed due to logic on product, system_ext, odm, or apex.
    // secilc is invoked to compile the above three policy files into a single monolithic policy
    // file. This file is then loaded into the kernel.

    const auto userdebug_plat_sepolicy = GetUserdebugPlatformPolicyFile();
    const bool use_userdebug_policy = userdebug_plat_sepolicy.has_value();
    if (use_userdebug_policy) {
        LOG(INFO) << "Using userdebug system sepolicy " << *userdebug_plat_sepolicy;
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

    std::string system_ext_compat_cil_file("/system_ext/etc/selinux/mapping/" + vend_plat_vers +
                                           ".compat.cil");
    if (access(system_ext_compat_cil_file.c_str(), F_OK) == -1) {
        system_ext_compat_cil_file.clear();
    }

    std::string product_policy_cil_file("/product/etc/selinux/product_sepolicy.cil");
    if (access(product_policy_cil_file.c_str(), F_OK) == -1) {
        product_policy_cil_file.clear();
    }

    std::string product_mapping_file("/product/etc/selinux/mapping/" + vend_plat_vers + ".cil");
    if (access(product_mapping_file.c_str(), F_OK) == -1) {
        product_mapping_file.clear();
    }

    std::string vendor_policy_cil_file("/vendor/etc/selinux/vendor_sepolicy.cil");
    if (access(vendor_policy_cil_file.c_str(), F_OK) == -1) {
        LOG(ERROR) << "Missing " << vendor_policy_cil_file;
        return false;
    }

    std::string plat_pub_versioned_cil_file("/vendor/etc/selinux/plat_pub_versioned.cil");
    if (access(plat_pub_versioned_cil_file.c_str(), F_OK) == -1) {
        LOG(ERROR) << "Missing " << plat_pub_versioned_cil_file;
        return false;
    }

    // odm_sepolicy.cil is default but optional.
    std::string odm_policy_cil_file("/odm/etc/selinux/odm_sepolicy.cil");
    if (access(odm_policy_cil_file.c_str(), F_OK) == -1) {
        odm_policy_cil_file.clear();
    }

    // apex_sepolicy.cil is default but optional.
    std::string apex_policy_cil_file("/dev/selinux/apex_sepolicy.cil");
    if (access(apex_policy_cil_file.c_str(), F_OK) == -1) {
        apex_policy_cil_file.clear();
    }
    const std::string version_as_string = std::to_string(SEPOLICY_VERSION);

    // clang-format off
    std::vector<const char*> compile_args {
        "/system/bin/secilc",
        use_userdebug_policy ? *userdebug_plat_sepolicy : plat_policy_cil_file,
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
    if (!system_ext_compat_cil_file.empty()) {
        compile_args.push_back(system_ext_compat_cil_file.c_str());
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
    if (!apex_policy_cil_file.empty()) {
        compile_args.push_back(apex_policy_cil_file.c_str());
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

constexpr const char* kSigningCertRelease =
        "/system/etc/selinux/com.android.sepolicy.cert-release.der";
constexpr const char* kFsVerityProcPath = "/proc/sys/fs/verity";
const std::string kSepolicyApexMetadataDir = "/metadata/sepolicy/";
const std::string kSepolicyApexSystemDir = "/system/etc/selinux/apex/";
const std::string kSepolicyZip = "SEPolicy.zip";
const std::string kSepolicySignature = "SEPolicy.zip.sig";

const std::string kTmpfsDir = "/dev/selinux/";

// Files that are deleted after policy is compiled/loaded.
const std::vector<std::string> kApexSepolicyTmp{"apex_sepolicy.cil", "apex_sepolicy.sha256"};
// Files that need to persist because they are used by userspace processes.
const std::vector<std::string> kApexSepolicy{"apex_file_contexts", "apex_property_contexts",
                                             "apex_service_contexts", "apex_seapp_contexts",
                                             "apex_test"};

Result<void> CreateTmpfsDirIfNeeded() {
    mode_t mode = 0744;
    struct stat stat_data;
    if (stat(kTmpfsDir.c_str(), &stat_data) != 0) {
        if (errno != ENOENT) {
            return ErrnoError() << "Could not stat " << kTmpfsDir;
        }
        if (mkdir(kTmpfsDir.c_str(), mode) != 0) {
            return ErrnoError() << "Could not mkdir " << kTmpfsDir;
        }
    } else {
        if (!S_ISDIR(stat_data.st_mode)) {
            return Error() << kTmpfsDir << " exists and is not a directory.";
        }
    }

    // Need to manually call chmod because mkdir will create a folder with
    // permissions mode & ~umask.
    if (chmod(kTmpfsDir.c_str(), mode) != 0) {
        return ErrnoError() << "Could not chmod " << kTmpfsDir;
    }

    return {};
}

Result<void> PutFileInTmpfs(ZipArchiveHandle archive, const std::string& fileName) {
    ZipEntry entry;
    std::string dstPath = kTmpfsDir + fileName;

    int ret = FindEntry(archive, fileName, &entry);
    if (ret != 0) {
        // All files are optional. If a file doesn't exist, return without error.
        return {};
    }

    unique_fd fd(TEMP_FAILURE_RETRY(
            open(dstPath.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, S_IRUSR | S_IWUSR)));
    if (fd == -1) {
        return ErrnoError() << "Failed to open " << dstPath;
    }

    ret = ExtractEntryToFile(archive, &entry, fd);
    if (ret != 0) {
        return Error() << "Failed to extract entry \"" << fileName << "\" ("
                       << entry.uncompressed_length << " bytes) to \"" << dstPath
                       << "\": " << ErrorCodeString(ret);
    }

    return {};
}

Result<void> GetPolicyFromApex(const std::string& dir) {
    LOG(INFO) << "Loading APEX Sepolicy from " << dir + kSepolicyZip;
    unique_fd fd(open((dir + kSepolicyZip).c_str(), O_RDONLY | O_BINARY | O_CLOEXEC));
    if (fd < 0) {
        return ErrnoError() << "Failed to open package " << dir + kSepolicyZip;
    }

    ZipArchiveHandle handle;
    int ret = OpenArchiveFd(fd.get(), (dir + kSepolicyZip).c_str(), &handle,
                            /*assume_ownership=*/false);
    if (ret < 0) {
        return Error() << "Failed to open package " << dir + kSepolicyZip << ": "
                       << ErrorCodeString(ret);
    }

    auto handle_guard = android::base::make_scope_guard([&handle] { CloseArchive(handle); });

    auto create = CreateTmpfsDirIfNeeded();
    if (!create.ok()) {
        return create.error();
    }

    for (const auto& file : kApexSepolicy) {
        auto extract = PutFileInTmpfs(handle, file);
        if (!extract.ok()) {
            return extract.error();
        }
    }
    for (const auto& file : kApexSepolicyTmp) {
        auto extract = PutFileInTmpfs(handle, file);
        if (!extract.ok()) {
            return extract.error();
        }
    }
    return {};
}

Result<void> LoadSepolicyApexCerts() {
    key_serial_t keyring_id = android::GetKeyringId(".fs-verity");
    if (keyring_id < 0) {
        return Error() << "Failed to find .fs-verity keyring id";
    }

    // TODO(b/199914227) the release key should always exist. Once it's checked in, start
    // throwing an error here if it doesn't exist.
    if (access(kSigningCertRelease, F_OK) == 0) {
        LoadKeyFromFile(keyring_id, "fsv_sepolicy_apex_release", kSigningCertRelease);
    }
    return {};
}

Result<void> SepolicyFsVerityCheck() {
    return Error() << "TODO implementent support for fsverity SEPolicy.";
}

Result<void> SepolicyCheckSignature(const std::string& dir) {
    std::string signature;
    if (!android::base::ReadFileToString(dir + kSepolicySignature, &signature)) {
        return ErrnoError() << "Failed to read " << kSepolicySignature;
    }

    std::fstream sepolicyZip(dir + kSepolicyZip, std::ios::in | std::ios::binary);
    if (!sepolicyZip) {
        return Error() << "Failed to open " << kSepolicyZip;
    }
    sepolicyZip.seekg(0);
    std::string sepolicyStr((std::istreambuf_iterator<char>(sepolicyZip)),
                            std::istreambuf_iterator<char>());

    auto releaseKey = extractPublicKeyFromX509(kSigningCertRelease);
    if (!releaseKey.ok()) {
        return releaseKey.error();
    }

    return verifySignature(sepolicyStr, signature, *releaseKey);
}

Result<void> SepolicyVerify(const std::string& dir, bool supportsFsVerity) {
    if (supportsFsVerity) {
        auto fsVerityCheck = SepolicyFsVerityCheck();
        if (fsVerityCheck.ok()) {
            return fsVerityCheck;
        }
        // TODO(b/199914227) If the device supports fsverity, but we fail here, we should fail to
        // boot and not carry on. For now, fallback to a signature checkuntil the fsverity
        // logic is implemented.
        LOG(INFO) << "Falling back to standard signature check. " << fsVerityCheck.error();
    }

    auto sepolicySignature = SepolicyCheckSignature(dir);
    if (!sepolicySignature.ok()) {
        return Error() << "Apex SEPolicy failed signature check";
    }
    return {};
}

void CleanupApexSepolicy() {
    for (const auto& file : kApexSepolicyTmp) {
        std::string path = kTmpfsDir + file;
        unlink(path.c_str());
    }
}

// Updatable sepolicy is shipped within an zip within an APEX. Because
// it needs to be available before Apexes are mounted, apexd copies
// the zip from the APEX and stores it in /metadata/sepolicy. If there is
// no updatable sepolicy in /metadata/sepolicy, then the updatable policy is
// loaded from /system/etc/selinux/apex. Init performs the following
// steps on boot:
//
// 1. Validates the zip by checking its signature against a public key that is
// stored in /system/etc/selinux.
// 2. Extracts files from zip and stores them in /dev/selinux.
// 3. Checks if the apex_sepolicy.sha256 matches the sha256 of precompiled_sepolicy.
// if so, the precompiled sepolicy is used. Otherwise, an on-device compile of the policy
// is used. This is the same flow as on-device compilation of policy for Treble.
// 4. Cleans up files in /dev/selinux which are no longer needed.
// 5. Restorecons the remaining files in /dev/selinux.
// 6. Sets selinux into enforcing mode and continues normal booting.
//
void PrepareApexSepolicy() {
    bool supportsFsVerity = access(kFsVerityProcPath, F_OK) == 0;
    if (supportsFsVerity) {
        auto loadSepolicyApexCerts = LoadSepolicyApexCerts();
        if (!loadSepolicyApexCerts.ok()) {
            // TODO(b/199914227) If the device supports fsverity, but we fail here, we should fail
            // to boot and not carry on. For now, fallback to a signature checkuntil the fsverity
            // logic is implemented.
            LOG(INFO) << loadSepolicyApexCerts.error();
        }
    }
    // If apex sepolicy zip exists in /metadata/sepolicy, use that, otherwise use version on
    // /system.
    auto dir = (access((kSepolicyApexMetadataDir + kSepolicyZip).c_str(), F_OK) == 0)
                       ? kSepolicyApexMetadataDir
                       : kSepolicyApexSystemDir;

    auto sepolicyVerify = SepolicyVerify(dir, supportsFsVerity);
    if (!sepolicyVerify.ok()) {
        LOG(INFO) << "Error: " << sepolicyVerify.error();
        // If signature verification fails, fall back to version on /system.
        // This file doesn't need to be verified because it lives on the system partition which
        // is signed and protected by verified boot.
        dir = kSepolicyApexSystemDir;
    }

    auto apex = GetPolicyFromApex(dir);
    if (!apex.ok()) {
        // TODO(b/199914227) Make failure fatal. For now continue booting with non-apex sepolicy.
        LOG(ERROR) << apex.error();
    }
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
    selinux_android_restorecon("/dev/console", 0);
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

    SkipMountingPartitions(&extra_fstab, true /* verbose */);
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

    PrepareApexSepolicy();

    // Read the policy before potentially killing snapuserd.
    std::string policy;
    ReadPolicy(&policy);
    CleanupApexSepolicy();

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

    // This restorecon is intentionally done before SelinuxSetEnforcement because the permissions
    // needed to transition files from tmpfs to *_contexts_file context should not be granted to
    // any process after selinux is set into enforcing mode.
    if (selinux_android_restorecon("/dev/selinux/", SELINUX_ANDROID_RESTORECON_RECURSE) == -1) {
        PLOG(FATAL) << "restorecon failed of /dev/selinux failed";
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

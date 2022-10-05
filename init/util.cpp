/*
 * Copyright (C) 2008 The Android Open Source Project
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

#include "util.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include <thread>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/scopeguard.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <cutils/sockets.h>
#include <selinux/android.h>

#ifdef INIT_FULL_SOURCES
#include <android/api-level.h>
#include <sys/system_properties.h>

#include "reboot_utils.h"
#include "selabel.h"
#include "selinux.h"
#else
#include "host_init_stubs.h"
#endif

using android::base::boot_clock;
using android::base::StartsWith;
using namespace std::literals::string_literals;

namespace android {
namespace init {

const std::string kDefaultAndroidDtDir("/proc/device-tree/firmware/android/");

void (*trigger_shutdown)(const std::string& command) = nullptr;

// DecodeUid() - decodes and returns the given string, which can be either the
// numeric or name representation, into the integer uid or gid.
Result<uid_t> DecodeUid(const std::string& name) {
    if (isalpha(name[0])) {
        passwd* pwd = getpwnam(name.c_str());
        if (!pwd) return ErrnoError() << "getpwnam failed";

        return pwd->pw_uid;
    }

    errno = 0;
    uid_t result = static_cast<uid_t>(strtoul(name.c_str(), 0, 0));
    if (errno) return ErrnoError() << "strtoul failed";

    return result;
}

/*
 * CreateSocket - creates a Unix domain socket in ANDROID_SOCKET_DIR
 * ("/dev/socket") as dictated in init.rc. This socket is inherited by the
 * daemon. We communicate the file descriptor's value via the environment
 * variable ANDROID_SOCKET_ENV_PREFIX<name> ("ANDROID_SOCKET_foo").
 */
Result<int> CreateSocket(const std::string& name, int type, bool passcred, bool should_listen,
                         mode_t perm, uid_t uid, gid_t gid, const std::string& socketcon) {
    if (!socketcon.empty()) {
        if (setsockcreatecon(socketcon.c_str()) == -1) {
            return ErrnoError() << "setsockcreatecon(\"" << socketcon << "\") failed";
        }
    }

    android::base::unique_fd fd(socket(PF_UNIX, type, 0));
    if (fd < 0) {
        return ErrnoError() << "Failed to open socket '" << name << "'";
    }

    if (!socketcon.empty()) setsockcreatecon(nullptr);

    struct sockaddr_un addr;
    memset(&addr, 0 , sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), ANDROID_SOCKET_DIR "/%s", name.c_str());

    if ((unlink(addr.sun_path) != 0) && (errno != ENOENT)) {
        return ErrnoError() << "Failed to unlink old socket '" << name << "'";
    }

    std::string secontext;
    if (SelabelLookupFileContext(addr.sun_path, S_IFSOCK, &secontext) && !secontext.empty()) {
        setfscreatecon(secontext.c_str());
    }

    if (passcred) {
        int on = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &on, sizeof(on))) {
            return ErrnoError() << "Failed to set SO_PASSCRED '" << name << "'";
        }
    }

    int ret = bind(fd, (struct sockaddr *) &addr, sizeof (addr));
    int savederrno = errno;

    if (!secontext.empty()) {
        setfscreatecon(nullptr);
    }

    auto guard = android::base::make_scope_guard([&addr] { unlink(addr.sun_path); });

    if (ret) {
        errno = savederrno;
        return ErrnoError() << "Failed to bind socket '" << name << "'";
    }

    if (lchown(addr.sun_path, uid, gid)) {
        return ErrnoError() << "Failed to lchown socket '" << addr.sun_path << "'";
    }
    if (fchmodat(AT_FDCWD, addr.sun_path, perm, AT_SYMLINK_NOFOLLOW)) {
        return ErrnoError() << "Failed to fchmodat socket '" << addr.sun_path << "'";
    }
    if (should_listen && listen(fd, /* use OS maximum */ 1 << 30)) {
        return ErrnoError() << "Failed to listen on socket '" << addr.sun_path << "'";
    }

    LOG(INFO) << "Created socket '" << addr.sun_path << "'"
              << ", mode " << std::oct << perm << std::dec
              << ", user " << uid
              << ", group " << gid;

    guard.Disable();
    return fd.release();
}

Result<std::string> ReadFile(const std::string& path) {
    android::base::unique_fd fd(
        TEMP_FAILURE_RETRY(open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC)));
    if (fd == -1) {
        return ErrnoError() << "open() failed";
    }

    // For security reasons, disallow world-writable
    // or group-writable files.
    struct stat sb;
    if (fstat(fd, &sb) == -1) {
        return ErrnoError() << "fstat failed()";
    }
    if ((sb.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        return Error() << "Skipping insecure file";
    }

    std::string content;
    if (!android::base::ReadFdToString(fd, &content)) {
        return ErrnoError() << "Unable to read file contents";
    }
    return content;
}

static int OpenFile(const std::string& path, int flags, mode_t mode) {
    std::string secontext;
    if (SelabelLookupFileContext(path, mode, &secontext) && !secontext.empty()) {
        setfscreatecon(secontext.c_str());
    }

    int rc = open(path.c_str(), flags, mode);

    if (!secontext.empty()) {
        int save_errno = errno;
        setfscreatecon(nullptr);
        errno = save_errno;
    }

    return rc;
}

Result<void> WriteFile(const std::string& path, const std::string& content) {
    android::base::unique_fd fd(TEMP_FAILURE_RETRY(
        OpenFile(path, O_WRONLY | O_CREAT | O_NOFOLLOW | O_TRUNC | O_CLOEXEC, 0600)));
    if (fd == -1) {
        return ErrnoError() << "open() failed";
    }
    if (!android::base::WriteStringToFd(content, fd)) {
        return ErrnoError() << "Unable to write file contents";
    }
    return {};
}

bool mkdir_recursive(const std::string& path, mode_t mode) {
    std::string::size_type slash = 0;
    while ((slash = path.find('/', slash + 1)) != std::string::npos) {
        auto directory = path.substr(0, slash);
        struct stat info;
        if (stat(directory.c_str(), &info) != 0) {
            auto ret = make_dir(directory, mode);
            if (!ret && errno != EEXIST) return false;
        }
    }
    auto ret = make_dir(path, mode);
    if (!ret && errno != EEXIST) return false;
    return true;
}

int wait_for_file(const char* filename, std::chrono::nanoseconds timeout) {
    android::base::Timer t;
    while (t.duration() < timeout) {
        struct stat sb;
        if (stat(filename, &sb) != -1) {
            LOG(INFO) << "wait for '" << filename << "' took " << t;
            return 0;
        }
        std::this_thread::sleep_for(10ms);
    }
    LOG(WARNING) << "wait for '" << filename << "' timed out and took " << t;
    return -1;
}

void ImportKernelCmdline(const std::function<void(const std::string&, const std::string&)>& fn) {
    std::string cmdline;
    android::base::ReadFileToString("/proc/cmdline", &cmdline);

    for (const auto& entry : android::base::Split(android::base::Trim(cmdline), " ")) {
        std::vector<std::string> pieces = android::base::Split(entry, "=");
        if (pieces.size() == 2) {
            fn(pieces[0], pieces[1]);
        }
    }
}

void ImportBootconfig(const std::function<void(const std::string&, const std::string&)>& fn) {
    std::string bootconfig;
    android::base::ReadFileToString("/proc/bootconfig", &bootconfig);

    for (const auto& entry : android::base::Split(bootconfig, "\n")) {
        std::vector<std::string> pieces = android::base::Split(entry, "=");
        if (pieces.size() == 2) {
            // get rid of the extra space between a list of values and remove the quotes.
            std::string value = android::base::StringReplace(pieces[1], "\", \"", ",", true);
            value.erase(std::remove(value.begin(), value.end(), '"'), value.end());
            fn(android::base::Trim(pieces[0]), android::base::Trim(value));
        }
    }
}

bool make_dir(const std::string& path, mode_t mode) {
    std::string secontext;
    if (SelabelLookupFileContext(path, mode, &secontext) && !secontext.empty()) {
        setfscreatecon(secontext.c_str());
    }

    int rc = mkdir(path.c_str(), mode);

    if (!secontext.empty()) {
        int save_errno = errno;
        setfscreatecon(nullptr);
        errno = save_errno;
    }

    return rc == 0;
}

/*
 * Returns true is pathname is a directory
 */
bool is_dir(const char* pathname) {
    struct stat info;
    if (stat(pathname, &info) == -1) {
        return false;
    }
    return S_ISDIR(info.st_mode);
}

Result<std::string> ExpandProps(const std::string& src) {
    const char* src_ptr = src.c_str();

    std::string dst;

    /* - variables can either be $x.y or ${x.y}, in case they are only part
     *   of the string.
     * - will accept $$ as a literal $.
     * - no nested property expansion, i.e. ${foo.${bar}} is not supported,
     *   bad things will happen
     * - ${x.y:-default} will return default value if property empty.
     */
    while (*src_ptr) {
        const char* c;

        c = strchr(src_ptr, '$');
        if (!c) {
            dst.append(src_ptr);
            return dst;
        }

        dst.append(src_ptr, c);
        c++;

        if (*c == '$') {
            dst.push_back(*(c++));
            src_ptr = c;
            continue;
        } else if (*c == '\0') {
            return dst;
        }

        std::string prop_name;
        std::string def_val;
        if (*c == '{') {
            c++;
            const char* end = strchr(c, '}');
            if (!end) {
                // failed to find closing brace, abort.
                return Error() << "unexpected end of string in '" << src << "', looking for }";
            }
            prop_name = std::string(c, end);
            c = end + 1;
            size_t def = prop_name.find(":-");
            if (def < prop_name.size()) {
                def_val = prop_name.substr(def + 2);
                prop_name = prop_name.substr(0, def);
            }
        } else {
            prop_name = c;
            if (SelinuxGetVendorAndroidVersion() >= __ANDROID_API_R__) {
                return Error() << "using deprecated syntax for specifying property '" << c
                               << "', use ${name} instead";
            } else {
                LOG(ERROR) << "using deprecated syntax for specifying property '" << c
                           << "', use ${name} instead";
            }
            c += prop_name.size();
        }

        if (prop_name.empty()) {
            return Error() << "invalid zero-length property name in '" << src << "'";
        }

        std::string prop_val = android::base::GetProperty(prop_name, "");
        if (prop_val.empty()) {
            if (def_val.empty()) {
                return Error() << "property '" << prop_name << "' doesn't exist while expanding '"
                               << src << "'";
            }
            prop_val = def_val;
        }

        dst.append(prop_val);
        src_ptr = c;
    }

    return dst;
}

static std::string init_android_dt_dir() {
    // Use the standard procfs-based path by default
    std::string android_dt_dir = kDefaultAndroidDtDir;
    // The platform may specify a custom Android DT path in kernel cmdline
    ImportKernelCmdline([&](const std::string& key, const std::string& value) {
        if (key == "androidboot.android_dt_dir") {
            android_dt_dir = value;
        }
    });
    // ..Or bootconfig
    if (android_dt_dir == kDefaultAndroidDtDir) {
        ImportBootconfig([&](const std::string& key, const std::string& value) {
            if (key == "androidboot.android_dt_dir") {
                android_dt_dir = value;
            }
        });
    }

    LOG(INFO) << "Using Android DT directory " << android_dt_dir;
    return android_dt_dir;
}

// FIXME: The same logic is duplicated in system/core/fs_mgr/
const std::string& get_android_dt_dir() {
    // Set once and saves time for subsequent calls to this function
    static const std::string kAndroidDtDir = init_android_dt_dir();
    return kAndroidDtDir;
}

// Reads the content of device tree file under the platform's Android DT directory.
// Returns true if the read is success, false otherwise.
bool read_android_dt_file(const std::string& sub_path, std::string* dt_content) {
    const std::string file_name = get_android_dt_dir() + sub_path;
    if (android::base::ReadFileToString(file_name, dt_content)) {
        if (!dt_content->empty()) {
            dt_content->pop_back();  // Trims the trailing '\0' out.
            return true;
        }
    }
    return false;
}

bool is_android_dt_value_expected(const std::string& sub_path, const std::string& expected_content) {
    std::string dt_content;
    if (read_android_dt_file(sub_path, &dt_content)) {
        if (dt_content == expected_content) {
            return true;
        }
    }
    return false;
}

bool IsLegalPropertyName(const std::string& name) {
    size_t namelen = name.size();

    if (namelen < 1) return false;
    if (name[0] == '.') return false;
    if (name[namelen - 1] == '.') return false;

    /* Only allow alphanumeric, plus '.', '-', '@', ':', or '_' */
    /* Don't allow ".." to appear in a property name */
    for (size_t i = 0; i < namelen; i++) {
        if (name[i] == '.') {
            // i=0 is guaranteed to never have a dot. See above.
            if (name[i - 1] == '.') return false;
            continue;
        }
        if (name[i] == '_' || name[i] == '-' || name[i] == '@' || name[i] == ':') continue;
        if (name[i] >= 'a' && name[i] <= 'z') continue;
        if (name[i] >= 'A' && name[i] <= 'Z') continue;
        if (name[i] >= '0' && name[i] <= '9') continue;
        return false;
    }

    return true;
}

Result<void> IsLegalPropertyValue(const std::string& name, const std::string& value) {
    if (value.size() >= PROP_VALUE_MAX && !StartsWith(name, "ro.")) {
        return Error() << "Property value too long";
    }

    if (mbstowcs(nullptr, value.data(), 0) == static_cast<std::size_t>(-1)) {
        return Error() << "Value is not a UTF8 encoded string";
    }

    return {};
}

static FscryptAction FscryptInferAction(const std::string& dir) {
    const std::string prefix = "/data/";

    if (!android::base::StartsWith(dir, prefix)) {
        return FscryptAction::kNone;
    }

    // Special-case /data/media/obb per b/64566063
    if (dir == "/data/media/obb") {
        // Try to set policy on this directory, but if it is non-empty this may fail.
        return FscryptAction::kAttempt;
    }

    // Only set policy on first level /data directories
    // To make this less restrictive, consider using a policy file.
    // However this is overkill for as long as the policy is simply
    // to apply a global policy to all /data folders created via makedir
    if (dir.find_first_of('/', prefix.size()) != std::string::npos) {
        return FscryptAction::kNone;
    }

    // Special case various directories that must not be encrypted,
    // often because their subdirectories must be encrypted.
    // This isn't a nice way to do this, see b/26641735
    std::vector<std::string> directories_to_exclude = {
            "lost+found", "system_ce", "system_de", "misc_ce",     "misc_de",
            "vendor_ce",  "vendor_de", "media",     "data",        "user",
            "user_de",    "apex",      "preloads",  "app-staging", "gsi",
    };
    for (const auto& d : directories_to_exclude) {
        if ((prefix + d) == dir) {
            return FscryptAction::kNone;
        }
    }
    // Empty these directories if policy setting fails.
    std::vector<std::string> wipe_on_failure = {
            "rollback", "rollback-observer",  // b/139193659
    };
    for (const auto& d : wipe_on_failure) {
        if ((prefix + d) == dir) {
            return FscryptAction::kDeleteIfNecessary;
        }
    }
    return FscryptAction::kRequire;
}

Result<MkdirOptions> ParseMkdir(const std::vector<std::string>& args) {
    mode_t mode = 0755;
    Result<uid_t> uid = -1;
    Result<gid_t> gid = -1;
    FscryptAction fscrypt_inferred_action = FscryptInferAction(args[1]);
    FscryptAction fscrypt_action = fscrypt_inferred_action;
    std::string ref_option = "ref";
    bool set_option_encryption = false;
    bool set_option_key = false;

    for (size_t i = 2; i < args.size(); i++) {
        switch (i) {
            case 2:
                mode = std::strtoul(args[2].c_str(), 0, 8);
                break;
            case 3:
                uid = DecodeUid(args[3]);
                if (!uid.ok()) {
                    return Error()
                           << "Unable to decode UID for '" << args[3] << "': " << uid.error();
                }
                break;
            case 4:
                gid = DecodeUid(args[4]);
                if (!gid.ok()) {
                    return Error()
                           << "Unable to decode GID for '" << args[4] << "': " << gid.error();
                }
                break;
            default:
                auto parts = android::base::Split(args[i], "=");
                if (parts.size() != 2) {
                    return Error() << "Can't parse option: '" << args[i] << "'";
                }
                auto optname = parts[0];
                auto optval = parts[1];
                if (optname == "encryption") {
                    if (set_option_encryption) {
                        return Error() << "Duplicated option: '" << optname << "'";
                    }
                    if (optval == "Require") {
                        fscrypt_action = FscryptAction::kRequire;
                    } else if (optval == "None") {
                        fscrypt_action = FscryptAction::kNone;
                    } else if (optval == "Attempt") {
                        fscrypt_action = FscryptAction::kAttempt;
                    } else if (optval == "DeleteIfNecessary") {
                        fscrypt_action = FscryptAction::kDeleteIfNecessary;
                    } else {
                        return Error() << "Unknown encryption option: '" << optval << "'";
                    }
                    set_option_encryption = true;
                } else if (optname == "key") {
                    if (set_option_key) {
                        return Error() << "Duplicated option: '" << optname << "'";
                    }
                    if (optval == "ref" || optval == "per_boot_ref") {
                        ref_option = optval;
                    } else {
                        return Error() << "Unknown key option: '" << optval << "'";
                    }
                    set_option_key = true;
                } else {
                    return Error() << "Unknown option: '" << args[i] << "'";
                }
        }
    }
    if (set_option_key && fscrypt_action == FscryptAction::kNone) {
        return Error() << "Key option set but encryption action is none";
    }
    const std::string prefix = "/data/";
    if (StartsWith(args[1], prefix) &&
        args[1].find_first_of('/', prefix.size()) == std::string::npos) {
        if (!set_option_encryption) {
            LOG(WARNING) << "Top-level directory needs encryption action, eg mkdir " << args[1]
                         << " <mode> <uid> <gid> encryption=Require";
        }
        if (fscrypt_action == FscryptAction::kNone) {
            LOG(INFO) << "Not setting encryption policy on: " << args[1];
        }
    }
    if (fscrypt_action != fscrypt_inferred_action) {
        LOG(WARNING) << "Inferred action different from explicit one, expected "
                     << static_cast<int>(fscrypt_inferred_action) << " but got "
                     << static_cast<int>(fscrypt_action);
    }

    return MkdirOptions{args[1], mode, *uid, *gid, fscrypt_action, ref_option};
}

Result<MountAllOptions> ParseMountAll(const std::vector<std::string>& args) {
    bool compat_mode = false;
    bool import_rc = false;
    if (SelinuxGetVendorAndroidVersion() <= __ANDROID_API_Q__) {
        if (args.size() <= 1) {
            return Error() << "mount_all requires at least 1 argument";
        }
        compat_mode = true;
        import_rc = true;
    }

    std::size_t first_option_arg = args.size();
    enum mount_mode mode = MOUNT_MODE_DEFAULT;

    // If we are <= Q, then stop looking for non-fstab arguments at slot 2.
    // Otherwise, stop looking at slot 1 (as the fstab path argument is optional >= R).
    for (std::size_t na = args.size() - 1; na > (compat_mode ? 1 : 0); --na) {
        if (args[na] == "--early") {
            first_option_arg = na;
            mode = MOUNT_MODE_EARLY;
        } else if (args[na] == "--late") {
            first_option_arg = na;
            mode = MOUNT_MODE_LATE;
            import_rc = false;
        }
    }

    std::string fstab_path;
    if (first_option_arg > 1) {
        fstab_path = args[1];
    } else if (compat_mode) {
        return Error() << "mount_all argument 1 must be the fstab path";
    }

    std::vector<std::string> rc_paths;
    for (std::size_t na = 2; na < first_option_arg; ++na) {
        rc_paths.push_back(args[na]);
    }

    return MountAllOptions{rc_paths, fstab_path, mode, import_rc};
}

Result<std::pair<int, std::vector<std::string>>> ParseRestorecon(
        const std::vector<std::string>& args) {
    struct flag_type {
        const char* name;
        int value;
    };
    static const flag_type flags[] = {
            {"--recursive", SELINUX_ANDROID_RESTORECON_RECURSE},
            {"--skip-ce", SELINUX_ANDROID_RESTORECON_SKIPCE},
            {"--cross-filesystems", SELINUX_ANDROID_RESTORECON_CROSS_FILESYSTEMS},
            {0, 0}};

    int flag = 0;
    std::vector<std::string> paths;

    bool in_flags = true;
    for (size_t i = 1; i < args.size(); ++i) {
        if (android::base::StartsWith(args[i], "--")) {
            if (!in_flags) {
                return Error() << "flags must precede paths";
            }
            bool found = false;
            for (size_t j = 0; flags[j].name; ++j) {
                if (args[i] == flags[j].name) {
                    flag |= flags[j].value;
                    found = true;
                    break;
                }
            }
            if (!found) {
                return Error() << "bad flag " << args[i];
            }
        } else {
            in_flags = false;
            paths.emplace_back(args[i]);
        }
    }
    return std::pair(flag, paths);
}

Result<std::string> ParseSwaponAll(const std::vector<std::string>& args) {
    if (args.size() <= 1) {
        if (SelinuxGetVendorAndroidVersion() <= __ANDROID_API_Q__) {
            return Error() << "swapon_all requires at least 1 argument";
        }
        return {};
    }
    return args[1];
}

Result<std::string> ParseUmountAll(const std::vector<std::string>& args) {
    if (args.size() <= 1) {
        if (SelinuxGetVendorAndroidVersion() <= __ANDROID_API_Q__) {
            return Error() << "umount_all requires at least 1 argument";
        }
        return {};
    }
    return args[1];
}

static void InitAborter(const char* abort_message) {
    // When init forks, it continues to use this aborter for LOG(FATAL), but we want children to
    // simply abort instead of trying to reboot the system.
    if (getpid() != 1) {
        android::base::DefaultAborter(abort_message);
        return;
    }

    InitFatalReboot(SIGABRT);
}

// The kernel opens /dev/console and uses that fd for stdin/stdout/stderr if there is a serial
// console enabled and no initramfs, otherwise it does not provide any fds for stdin/stdout/stderr.
// SetStdioToDevNull() is used to close these existing fds if they exist and replace them with
// /dev/null regardless.
//
// In the case that these fds are provided by the kernel, the exec of second stage init causes an
// SELinux denial as it does not have access to /dev/console.  In the case that they are not
// provided, exec of any further process is potentially dangerous as the first fd's opened by that
// process will take the stdin/stdout/stderr fileno's, which can cause issues if printf(), etc is
// then used by that process.
//
// Lastly, simply calling SetStdioToDevNull() in first stage init is not enough, since first
// stage init still runs in kernel context, future child processes will not have permissions to
// access any fds that it opens, including the one opened below for /dev/null.  Therefore,
// SetStdioToDevNull() must be called again in second stage init.
void SetStdioToDevNull(char** argv) {
    // Make stdin/stdout/stderr all point to /dev/null.
    int fd = open("/dev/null", O_RDWR);  // NOLINT(android-cloexec-open)
    if (fd == -1) {
        int saved_errno = errno;
        android::base::InitLogging(argv, &android::base::KernelLogger, InitAborter);
        errno = saved_errno;
        PLOG(FATAL) << "Couldn't open /dev/null";
    }
    dup2(fd, STDIN_FILENO);
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    if (fd > STDERR_FILENO) close(fd);
}

void InitKernelLogging(char** argv) {
    SetFatalRebootTarget();
    android::base::InitLogging(argv, &android::base::KernelLogger, InitAborter);
}

bool IsRecoveryMode() {
    return access("/system/bin/recovery", F_OK) == 0;
}

// Check if default mount namespace is ready to be used with APEX modules
static bool is_default_mount_namespace_ready = false;

bool IsDefaultMountNamespaceReady() {
    return is_default_mount_namespace_ready;
}

void SetDefaultMountNamespaceReady() {
    is_default_mount_namespace_ready = true;
}

bool IsMicrodroid() {
    static bool is_microdroid = android::base::GetProperty("ro.hardware", "") == "microdroid";
    return is_microdroid;
}

}  // namespace init
}  // namespace android

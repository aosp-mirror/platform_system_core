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
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <cutils/sockets.h>
#include <selinux/android.h>

#if defined(__ANDROID__)
#include "reboot_utils.h"
#include "selabel.h"
#else
#include "host_init_stubs.h"
#endif

#ifdef _INIT_INIT_H
#error "Do not include init.h in files used by ueventd; it will expose init's globals"
#endif

using android::base::boot_clock;
using namespace std::literals::string_literals;

namespace android {
namespace init {

const std::string kDefaultAndroidDtDir("/proc/device-tree/firmware/android/");

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
int CreateSocket(const char* name, int type, bool passcred, mode_t perm, uid_t uid, gid_t gid,
                 const char* socketcon) {
    if (socketcon) {
        if (setsockcreatecon(socketcon) == -1) {
            PLOG(ERROR) << "setsockcreatecon(\"" << socketcon << "\") failed";
            return -1;
        }
    }

    android::base::unique_fd fd(socket(PF_UNIX, type, 0));
    if (fd < 0) {
        PLOG(ERROR) << "Failed to open socket '" << name << "'";
        return -1;
    }

    if (socketcon) setsockcreatecon(NULL);

    struct sockaddr_un addr;
    memset(&addr, 0 , sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), ANDROID_SOCKET_DIR"/%s",
             name);

    if ((unlink(addr.sun_path) != 0) && (errno != ENOENT)) {
        PLOG(ERROR) << "Failed to unlink old socket '" << name << "'";
        return -1;
    }

    std::string secontext;
    if (SelabelLookupFileContext(addr.sun_path, S_IFSOCK, &secontext) && !secontext.empty()) {
        setfscreatecon(secontext.c_str());
    }

    if (passcred) {
        int on = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &on, sizeof(on))) {
            PLOG(ERROR) << "Failed to set SO_PASSCRED '" << name << "'";
            return -1;
        }
    }

    int ret = bind(fd, (struct sockaddr *) &addr, sizeof (addr));
    int savederrno = errno;

    if (!secontext.empty()) {
        setfscreatecon(nullptr);
    }

    if (ret) {
        errno = savederrno;
        PLOG(ERROR) << "Failed to bind socket '" << name << "'";
        goto out_unlink;
    }

    if (lchown(addr.sun_path, uid, gid)) {
        PLOG(ERROR) << "Failed to lchown socket '" << addr.sun_path << "'";
        goto out_unlink;
    }
    if (fchmodat(AT_FDCWD, addr.sun_path, perm, AT_SYMLINK_NOFOLLOW)) {
        PLOG(ERROR) << "Failed to fchmodat socket '" << addr.sun_path << "'";
        goto out_unlink;
    }

    LOG(INFO) << "Created socket '" << addr.sun_path << "'"
              << ", mode " << std::oct << perm << std::dec
              << ", user " << uid
              << ", group " << gid;

    return fd.release();

out_unlink:
    unlink(addr.sun_path);
    return -1;
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

Result<Success> WriteFile(const std::string& path, const std::string& content) {
    android::base::unique_fd fd(TEMP_FAILURE_RETRY(
        OpenFile(path, O_WRONLY | O_CREAT | O_NOFOLLOW | O_TRUNC | O_CLOEXEC, 0600)));
    if (fd == -1) {
        return ErrnoError() << "open() failed";
    }
    if (!android::base::WriteStringToFd(content, fd)) {
        return ErrnoError() << "Unable to write file contents";
    }
    return Success();
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

void import_kernel_cmdline(bool in_qemu,
                           const std::function<void(const std::string&, const std::string&, bool)>& fn) {
    std::string cmdline;
    android::base::ReadFileToString("/proc/cmdline", &cmdline);

    for (const auto& entry : android::base::Split(android::base::Trim(cmdline), " ")) {
        std::vector<std::string> pieces = android::base::Split(entry, "=");
        if (pieces.size() == 2) {
            fn(pieces[0], pieces[1], in_qemu);
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

bool expand_props(const std::string& src, std::string* dst) {
    const char* src_ptr = src.c_str();

    if (!dst) {
        return false;
    }

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
            dst->append(src_ptr);
            return true;
        }

        dst->append(src_ptr, c);
        c++;

        if (*c == '$') {
            dst->push_back(*(c++));
            src_ptr = c;
            continue;
        } else if (*c == '\0') {
            return true;
        }

        std::string prop_name;
        std::string def_val;
        if (*c == '{') {
            c++;
            const char* end = strchr(c, '}');
            if (!end) {
                // failed to find closing brace, abort.
                LOG(ERROR) << "unexpected end of string in '" << src << "', looking for }";
                return false;
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
            LOG(ERROR) << "using deprecated syntax for specifying property '" << c << "', use ${name} instead";
            c += prop_name.size();
        }

        if (prop_name.empty()) {
            LOG(ERROR) << "invalid zero-length property name in '" << src << "'";
            return false;
        }

        std::string prop_val = android::base::GetProperty(prop_name, "");
        if (prop_val.empty()) {
            if (def_val.empty()) {
                LOG(ERROR) << "property '" << prop_name << "' doesn't exist while expanding '" << src << "'";
                return false;
            }
            prop_val = def_val;
        }

        dst->append(prop_val);
        src_ptr = c;
    }

    return true;
}

static std::string init_android_dt_dir() {
    // Use the standard procfs-based path by default
    std::string android_dt_dir = kDefaultAndroidDtDir;
    // The platform may specify a custom Android DT path in kernel cmdline
    import_kernel_cmdline(false,
                          [&](const std::string& key, const std::string& value, bool in_qemu) {
                              if (key == "androidboot.android_dt_dir") {
                                  android_dt_dir = value;
                              }
                          });
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

static void InitAborter(const char* abort_message) {
    // When init forks, it continues to use this aborter for LOG(FATAL), but we want children to
    // simply abort instead of trying to reboot the system.
    if (getpid() != 1) {
        android::base::DefaultAborter(abort_message);
        return;
    }

    InitFatalReboot();
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
    int fd = open("/dev/null", O_RDWR);
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

}  // namespace init
}  // namespace android

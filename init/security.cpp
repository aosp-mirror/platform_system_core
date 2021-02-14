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

#include "security.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/perf_event.h>
#include <selinux/selinux.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <fstream>

#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/unique_fd.h>

using android::base::unique_fd;
using android::base::SetProperty;

namespace android {
namespace init {

static bool SetHighestAvailableOptionValue(const std::string& path, int min, int max) {
    std::ifstream inf(path, std::fstream::in);
    if (!inf) {
        LOG(ERROR) << "Cannot open for reading: " << path;
        return false;
    }

    int current = max;
    while (current >= min) {
        // try to write out new value
        std::string str_val = std::to_string(current);
        std::ofstream of(path, std::fstream::out);
        if (!of) {
            LOG(ERROR) << "Cannot open for writing: " << path;
            return false;
        }
        of << str_val << std::endl;
        of.close();

        // check to make sure it was recorded
        inf.seekg(0);
        std::string str_rec;
        inf >> str_rec;
        if (str_val.compare(str_rec) == 0) {
            break;
        }
        current--;
    }
    inf.close();

    if (current < min) {
        LOG(ERROR) << "Unable to set minimum option value " << min << " in " << path;
        return false;
    }
    return true;
}

#define MMAP_RND_PATH "/proc/sys/vm/mmap_rnd_bits"
#define MMAP_RND_COMPAT_PATH "/proc/sys/vm/mmap_rnd_compat_bits"

static bool SetMmapRndBitsMin(int start, int min, bool compat) {
    std::string path;
    if (compat) {
        path = MMAP_RND_COMPAT_PATH;
    } else {
        path = MMAP_RND_PATH;
    }

    return SetHighestAvailableOptionValue(path, min, start);
}

// Set /proc/sys/vm/mmap_rnd_bits and potentially
// /proc/sys/vm/mmap_rnd_compat_bits to the maximum supported values.
// Returns -1 if unable to set these to an acceptable value.
//
// To support this sysctl, the following upstream commits are needed:
//
// d07e22597d1d mm: mmap: add new /proc tunable for mmap_base ASLR
// e0c25d958f78 arm: mm: support ARCH_MMAP_RND_BITS
// 8f0d3aa9de57 arm64: mm: support ARCH_MMAP_RND_BITS
// 9e08f57d684a x86: mm: support ARCH_MMAP_RND_BITS
// ec9ee4acd97c drivers: char: random: add get_random_long()
// 5ef11c35ce86 mm: ASLR: use get_random_long()
Result<void> SetMmapRndBitsAction(const BuiltinArguments&) {
// values are arch-dependent
#if defined(USER_MODE_LINUX)
    // uml does not support mmap_rnd_bits
    return {};
#elif defined(__aarch64__)
    // arm64 supports 18 - 33 bits depending on pagesize and VA_SIZE
    if (SetMmapRndBitsMin(33, 24, false) && SetMmapRndBitsMin(16, 16, true)) {
        return {};
    }
#elif defined(__x86_64__)
    // x86_64 supports 28 - 32 bits
    if (SetMmapRndBitsMin(32, 32, false) && SetMmapRndBitsMin(16, 16, true)) {
        return {};
    }
#elif defined(__arm__) || defined(__i386__)
    // check to see if we're running on 64-bit kernel
    bool h64 = !access(MMAP_RND_COMPAT_PATH, F_OK);
    // supported 32-bit architecture must have 16 bits set
    if (SetMmapRndBitsMin(16, 16, h64)) {
        return {};
    }
#else
    LOG(ERROR) << "Unknown architecture";
#endif

    LOG(FATAL) << "Unable to set adequate mmap entropy value!";
    return Error();
}

#define KPTR_RESTRICT_PATH "/proc/sys/kernel/kptr_restrict"
#define KPTR_RESTRICT_MINVALUE 2
#define KPTR_RESTRICT_MAXVALUE 4

// Set kptr_restrict to the highest available level.
//
// Aborts if unable to set this to an acceptable value.
Result<void> SetKptrRestrictAction(const BuiltinArguments&) {
    std::string path = KPTR_RESTRICT_PATH;

    if (!SetHighestAvailableOptionValue(path, KPTR_RESTRICT_MINVALUE, KPTR_RESTRICT_MAXVALUE)) {
        LOG(FATAL) << "Unable to set adequate kptr_restrict value!";
        return Error();
    }
    return {};
}

// Test for whether the kernel has SELinux hooks for the perf_event_open()
// syscall. If the hooks are present, we can stop using the other permission
// mechanism (perf_event_paranoid sysctl), and use only the SELinux policy to
// control access to the syscall. The hooks are expected on all Android R
// release kernels, but might be absent on devices that upgrade while keeping an
// older kernel.
//
// There is no direct/synchronous way of finding out that a syscall failed due
// to SELinux. Therefore we test for a combination of a success and a failure
// that are explained by the platform's SELinux policy for the "init" domain:
// * cpu-scoped perf_event is allowed
// * ioctl() on the event fd is disallowed with EACCES
//
// Since init has CAP_SYS_ADMIN, these tests are not affected by the system-wide
// perf_event_paranoid sysctl.
//
// If the SELinux hooks are detected, a special sysprop
// (sys.init.perf_lsm_hooks) is set, which translates to a modification of
// perf_event_paranoid (through init.rc sysprop actions).
//
// TODO(b/137092007): this entire test can be removed once the platform stops
// supporting kernels that precede the perf_event_open hooks (Android common
// kernels 4.4 and 4.9).
Result<void> TestPerfEventSelinuxAction(const BuiltinArguments&) {
    // Special case: for *development devices* that boot with permissive
    // SELinux, treat the LSM hooks as present for the effect of lowering the
    // perf_event_paranoid sysctl. The sysprop is reused for pragmatic reasons,
    // as there no existing way for init rules to check for permissive boot at
    // the time of writing.
    if (ALLOW_PERMISSIVE_SELINUX) {
        if (!security_getenforce()) {
            LOG(INFO) << "Permissive SELinux boot, forcing sys.init.perf_lsm_hooks to 1.";
            SetProperty("sys.init.perf_lsm_hooks", "1");
            return {};
        }
    }

    // Use a trivial event that will be configured, but not started.
    struct perf_event_attr pe = {
            .type = PERF_TYPE_SOFTWARE,
            .size = sizeof(struct perf_event_attr),
            .config = PERF_COUNT_SW_TASK_CLOCK,
            .disabled = 1,
            .exclude_kernel = 1,
    };

    // Open the above event targeting cpu 0. (EINTR not possible.)
    unique_fd fd(static_cast<int>(syscall(__NR_perf_event_open, &pe, /*pid=*/-1,
                                          /*cpu=*/0,
                                          /*group_fd=*/-1, /*flags=*/0)));
    if (fd == -1) {
        PLOG(ERROR) << "Unexpected perf_event_open error";
        return {};
    }

    int ioctl_ret = ioctl(fd, PERF_EVENT_IOC_RESET);
    if (ioctl_ret != -1) {
        // Success implies that the kernel doesn't have the hooks.
        return {};
    } else if (errno != EACCES) {
        PLOG(ERROR) << "Unexpected perf_event ioctl error";
        return {};
    }

    // Conclude that the SELinux hooks are present.
    SetProperty("sys.init.perf_lsm_hooks", "1");
    return {};
}

}  // namespace init
}  // namespace android

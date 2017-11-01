/*
 * Copyright (C) 2015 The Android Open Source Project
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

#include "log.h"

#include <fcntl.h>
#include <linux/audit.h>
#include <string.h>
#include <unistd.h>

#include <android-base/logging.h>
#include <cutils/android_reboot.h>
#include <selinux/selinux.h>

#include "reboot.h"

namespace android {
namespace init {

static void InitAborter(const char* abort_message) {
    // When init forks, it continues to use this aborter for LOG(FATAL), but we want children to
    // simply abort instead of trying to reboot the system.
    if (getpid() != 1) {
        android::base::DefaultAborter(abort_message);
        return;
    }

    // DoReboot() does a lot to try to shutdown the system cleanly.  If something happens to call
    // LOG(FATAL) in the shutdown path, we want to catch this and immediately use the syscall to
    // reboot instead of recursing here.
    static bool has_aborted = false;
    if (!has_aborted) {
        has_aborted = true;
        // Do not queue "shutdown" trigger since we want to shutdown immediately and it's not likely
        // that we can even run the ActionQueue at this point.
        DoReboot(ANDROID_RB_RESTART2, "reboot", "bootloader", false);
    } else {
        RebootSystem(ANDROID_RB_RESTART2, "bootloader");
    }
}

void InitKernelLogging(char* argv[]) {
    // Make stdin/stdout/stderr all point to /dev/null.
    int fd = open("/sys/fs/selinux/null", O_RDWR);
    if (fd == -1) {
        int saved_errno = errno;
        android::base::InitLogging(argv, &android::base::KernelLogger, InitAborter);
        errno = saved_errno;
        PLOG(FATAL) << "Couldn't open /sys/fs/selinux/null";
    }
    dup2(fd, 0);
    dup2(fd, 1);
    dup2(fd, 2);
    if (fd > 2) close(fd);

    android::base::InitLogging(argv, &android::base::KernelLogger, InitAborter);
}

int selinux_klog_callback(int type, const char *fmt, ...) {
    android::base::LogSeverity severity = android::base::ERROR;
    if (type == SELINUX_WARNING) {
        severity = android::base::WARNING;
    } else if (type == SELINUX_INFO) {
        severity = android::base::INFO;
    }
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    android::base::KernelLogger(android::base::MAIN, severity, "selinux", nullptr, 0, buf);
    return 0;
}

}  // namespace init
}  // namespace android

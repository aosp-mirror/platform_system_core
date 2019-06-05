/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include <sys/capability.h>
#include <sys/reboot.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <android-base/logging.h>
#include <cutils/android_reboot.h>

#include "capabilities.h"

namespace android {
namespace init {

bool IsRebootCapable() {
    if (!CAP_IS_SUPPORTED(CAP_SYS_BOOT)) {
        PLOG(WARNING) << "CAP_SYS_BOOT is not supported";
        return true;
    }

    ScopedCaps caps(cap_get_proc());
    if (!caps) {
        PLOG(WARNING) << "cap_get_proc() failed";
        return true;
    }

    cap_flag_value_t value = CAP_SET;
    if (cap_get_flag(caps.get(), CAP_SYS_BOOT, CAP_EFFECTIVE, &value) != 0) {
        PLOG(WARNING) << "cap_get_flag(CAP_SYS_BOOT, EFFECTIVE) failed";
        return true;
    }
    return value == CAP_SET;
}

void __attribute__((noreturn)) RebootSystem(unsigned int cmd, const std::string& rebootTarget) {
    LOG(INFO) << "Reboot ending, jumping to kernel";

    if (!IsRebootCapable()) {
        // On systems where init does not have the capability of rebooting the
        // device, just exit cleanly.
        exit(0);
    }

    switch (cmd) {
        case ANDROID_RB_POWEROFF:
            reboot(RB_POWER_OFF);
            break;

        case ANDROID_RB_RESTART2:
            syscall(__NR_reboot, LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2,
                    LINUX_REBOOT_CMD_RESTART2, rebootTarget.c_str());
            break;

        case ANDROID_RB_THERMOFF:
            reboot(RB_POWER_OFF);
            break;
    }
    // In normal case, reboot should not return.
    PLOG(ERROR) << "reboot call returned";
    abort();
}

void InstallRebootSignalHandlers() {
    // Instead of panic'ing the kernel as is the default behavior when init crashes,
    // we prefer to reboot to bootloader on development builds, as this will prevent
    // boot looping bad configurations and allow both developers and test farms to easily
    // recover.
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    sigfillset(&action.sa_mask);
    action.sa_handler = [](int signal) {
        // These signal handlers are also caught for processes forked from init, however we do not
        // want them to trigger reboot, so we directly call _exit() for children processes here.
        if (getpid() != 1) {
            _exit(signal);
        }

        // Calling DoReboot() or LOG(FATAL) is not a good option as this is a signal handler.
        // RebootSystem uses syscall() which isn't actually async-signal-safe, but our only option
        // and probably good enough given this is already an error case and only enabled for
        // development builds.
        RebootSystem(ANDROID_RB_RESTART2, "bootloader");
    };
    action.sa_flags = SA_RESTART;
    sigaction(SIGABRT, &action, nullptr);
    sigaction(SIGBUS, &action, nullptr);
    sigaction(SIGFPE, &action, nullptr);
    sigaction(SIGILL, &action, nullptr);
    sigaction(SIGSEGV, &action, nullptr);
#if defined(SIGSTKFLT)
    sigaction(SIGSTKFLT, &action, nullptr);
#endif
    sigaction(SIGSYS, &action, nullptr);
    sigaction(SIGTRAP, &action, nullptr);
}

}  // namespace init
}  // namespace android

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

#include <optional>
#include <string>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <cutils/android_reboot.h>
#include <unwindstack/AndroidUnwinder.h>

#include "capabilities.h"
#include "reboot_utils.h"
#include "util.h"

namespace android {
namespace init {

static std::string init_fatal_reboot_target = "bootloader";
static bool init_fatal_panic = false;

// this needs to read the /proc/* files directly because it is called before
// ro.boot.* properties are initialized
void SetFatalRebootTarget(const std::optional<std::string>& reboot_target) {
    std::string cmdline;
    android::base::ReadFileToString("/proc/cmdline", &cmdline);
    cmdline = android::base::Trim(cmdline);

    const std::string kInitFatalPanicParamString = "androidboot.init_fatal_panic";
    if (cmdline.find(kInitFatalPanicParamString) == std::string::npos) {
        init_fatal_panic = false;
        ImportBootconfig(
                [kInitFatalPanicParamString](const std::string& key, const std::string& value) {
                    if (key == kInitFatalPanicParamString && value == "true") {
                        init_fatal_panic = true;
                    }
                });
    } else {
        const std::string kInitFatalPanicString = kInitFatalPanicParamString + "=true";
        init_fatal_panic = cmdline.find(kInitFatalPanicString) != std::string::npos;
    }

    if (reboot_target) {
        init_fatal_reboot_target = *reboot_target;
        return;
    }

    const std::string kRebootTargetString = "androidboot.init_fatal_reboot_target";
    auto start_pos = cmdline.find(kRebootTargetString);
    if (start_pos == std::string::npos) {
        ImportBootconfig([kRebootTargetString](const std::string& key, const std::string& value) {
            if (key == kRebootTargetString) {
                init_fatal_reboot_target = value;
            }
        });
        // We already default to bootloader if no setting is provided.
    } else {
        const std::string kRebootTargetStringPattern = kRebootTargetString + "=";
        start_pos += sizeof(kRebootTargetStringPattern) - 1;

        auto end_pos = cmdline.find(' ', start_pos);
        // if end_pos isn't found, then we've run off the end, but this is okay as this is the last
        // entry, and -1 is a valid size for string::substr();
        auto size = end_pos == std::string::npos ? -1 : end_pos - start_pos;
        init_fatal_reboot_target = cmdline.substr(start_pos, size);
    }
}

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

void __attribute__((noreturn))
RebootSystem(unsigned int cmd, const std::string& rebootTarget, const std::string& reboot_reason) {
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
            if (android::base::GetBoolProperty("ro.thermal_warmreset", false)) {
                std::string reason = "shutdown,thermal";
                if (!reboot_reason.empty()) reason = reboot_reason;

                LOG(INFO) << "Try to trigger a warm reset for thermal shutdown";
                syscall(__NR_reboot, LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2,
                        LINUX_REBOOT_CMD_RESTART2, reason.c_str());
            } else {
                reboot(RB_POWER_OFF);
            }
            break;
    }
    // In normal case, reboot should not return.
    PLOG(ERROR) << "reboot call returned";
    abort();
}

void __attribute__((noreturn)) InitFatalReboot(int signal_number) {
    auto pid = fork();

    if (pid == -1) {
        // Couldn't fork, don't even try to backtrace, just reboot.
        RebootSystem(ANDROID_RB_RESTART2, init_fatal_reboot_target);
    } else if (pid == 0) {
        // Fork a child for safety, since we always want to shut down if something goes wrong, but
        // its worth trying to get the backtrace, even in the signal handler, since typically it
        // does work despite not being async-signal-safe.
        sleep(5);
        RebootSystem(ANDROID_RB_RESTART2, init_fatal_reboot_target);
    }

    // In the parent, let's try to get a backtrace then shutdown.
    LOG(ERROR) << __FUNCTION__ << ": signal " << signal_number;
    unwindstack::AndroidLocalUnwinder unwinder;
    unwindstack::AndroidUnwinderData data;
    if (!unwinder.Unwind(data)) {
        LOG(ERROR) << __FUNCTION__ << ": Failed to unwind callstack: " << data.GetErrorString();
    }
    for (const auto& frame : data.frames) {
        LOG(ERROR) << unwinder.FormatFrame(frame);
    }
    if (init_fatal_panic) {
        LOG(ERROR) << __FUNCTION__ << ": Trigger crash";
        android::base::WriteStringToFile("c", PROC_SYSRQ);
        LOG(ERROR) << __FUNCTION__ << ": Sys-Rq failed to crash the system; fallback to exit().";
        _exit(signal_number);
    }
    RebootSystem(ANDROID_RB_RESTART2, init_fatal_reboot_target);
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
        InitFatalReboot(signal);
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

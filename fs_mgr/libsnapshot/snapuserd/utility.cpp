// Copyright (C) 2023 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "utility.h"

#include <android-base/properties.h>
#include <sys/resource.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <libdm/dm.h>
#include <processgroup/processgroup.h>

#include <private/android_filesystem_config.h>

namespace android {
namespace snapshot {

using android::base::unique_fd;
using android::dm::DeviceMapper;

bool SetThreadPriority([[maybe_unused]] int priority) {
#ifdef __ANDROID__
    return setpriority(PRIO_PROCESS, gettid(), priority) != -1;
#else
    return true;
#endif
}

bool SetProfiles([[maybe_unused]] std::initializer_list<std::string_view> profiles) {
#ifdef __ANDROID__
    if (setgid(AID_SYSTEM)) {
        return false;
    }
    return SetTaskProfiles(gettid(), profiles);
#else
    return true;
#endif
}

bool KernelSupportsIoUring() {
    struct utsname uts {};
    unsigned int major, minor;

    uname(&uts);
    if (sscanf(uts.release, "%u.%u", &major, &minor) != 2) {
        return false;
    }

    // We will only support kernels from 5.6 onwards as IOSQE_ASYNC flag and
    // IO_URING_OP_READ/WRITE opcodes were introduced only on 5.6 kernel
    return major > 5 || (major == 5 && minor >= 6);
}

bool GetUserspaceSnapshotsEnabledProperty() {
    return android::base::GetBoolProperty("ro.virtual_ab.userspace.snapshots.enabled", false);
}

bool KernelSupportsCompressedSnapshots() {
    auto& dm = DeviceMapper::Instance();
    return dm.GetTargetByName("user", nullptr);
}

bool IsVendorFromAndroid12() {
    const std::string UNKNOWN = "unknown";
    const std::string vendor_release =
            android::base::GetProperty("ro.vendor.build.version.release_or_codename", UNKNOWN);

    if (vendor_release.find("12") != std::string::npos) {
        return true;
    }
    return false;
}

bool CanUseUserspaceSnapshots() {
    if (!GetUserspaceSnapshotsEnabledProperty()) {
        LOG(INFO) << "Virtual A/B - Userspace snapshots disabled";
        return false;
    }

    if (!KernelSupportsCompressedSnapshots()) {
        LOG(ERROR) << "Userspace snapshots requested, but no kernel support is available.";
        return false;
    }
    return true;
}

}  // namespace snapshot
}  // namespace android

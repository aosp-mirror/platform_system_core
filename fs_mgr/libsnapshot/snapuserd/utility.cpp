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

#include <sys/resource.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <android-base/file.h>

namespace android {
namespace snapshot {

using android::base::unique_fd;

bool SetThreadPriority([[maybe_unused]] int priority) {
#ifdef __ANDROID__
    return setpriority(PRIO_PROCESS, gettid(), priority) != -1;
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

}  // namespace snapshot
}  // namespace android

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

#include "diagnose_usb.h"

#include <errno.h>
#include <unistd.h>

#include <string>

#include <android-base/stringprintf.h>

#if defined(__linux__)
#include <grp.h>
#endif

static const char kPermissionsHelpUrl[] = "http://developer.android.com/tools/device.html";

// Returns a message describing any potential problems we find with udev, or nullptr if we can't
// find plugdev information (i.e. udev is not installed).
static const char* GetUdevProblem() {
#if defined(__linux__)
    errno = 0;
    group* plugdev_group = getgrnam("plugdev");

    if (plugdev_group == nullptr) {
        if (errno != 0) {
            perror("failed to read plugdev group info");
        }
        // We can't give any generally useful advice here, just let the caller print the help URL.
        return nullptr;
    }

    // getgroups(2) indicates that the group_member() may not check the egid so we check it
    // additionally just to be sure.
    if (group_member(plugdev_group->gr_gid) || getegid() == plugdev_group->gr_gid) {
        // The user is in plugdev so the problem is likely with the udev rules.
        return "verify udev rules";
    }
    return "udev requires plugdev group membership";
#else
    return nullptr;
#endif
}

// Short help text must be a single line, and will look something like:
//   no permissions (reason); see <URL>
std::string UsbNoPermissionsShortHelpText() {
    std::string help_text = "no permissions";

    const char* problem = GetUdevProblem();
    if (problem != nullptr) {
        help_text += android::base::StringPrintf(" (%s)", problem);
    }

    return android::base::StringPrintf("%s; see [%s]", help_text.c_str(), kPermissionsHelpUrl);
}

// Long help text can span multiple lines and should provide more detailed information.
std::string UsbNoPermissionsLongHelpText() {
    std::string header = "insufficient permissions for device";

    const char* problem = GetUdevProblem();
    if (problem != nullptr) {
        header += android::base::StringPrintf(": %s", problem);
    }

    return android::base::StringPrintf("%s.\nSee [%s] for more information.",
                                       header.c_str(), kPermissionsHelpUrl);
}

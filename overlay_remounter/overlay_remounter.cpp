/*
 * Copyright (C) 2025 The Android Open Source Project
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

#include <sys/mount.h>
#include <unistd.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/strings.h>

int main(int /*argc*/, char** argv) {
    android::base::InitLogging(argv, &android::base::KernelLogger);
    LOG(INFO) << "Overlay remounter will remount all overlay mount points in the overlay_remounter "
                 "domain";

    // Remount ouerlayfs
    std::string contents;
    auto result = android::base::ReadFileToString("/proc/mounts", &contents, true);

    auto lines = android::base::Split(contents, "\n");
    for (auto const& line : lines) {
        if (!android::base::StartsWith(line, "overlay")) {
            continue;
        }
        auto bits = android::base::Split(line, " ");
        if (int result = umount(bits[1].c_str()); result == -1) {
            PLOG(FATAL) << "umount FAILED: " << bits[1];
        }
        std::string options;
        for (auto const& option : android::base::Split(bits[3], ",")) {
            if (option == "ro" || option == "seclabel" || option == "noatime") continue;
            if (!options.empty()) options += ',';
            options += option;
        }
        result = mount("overlay", bits[1].c_str(), "overlay", MS_RDONLY | MS_NOATIME,
                       options.c_str());
        if (result == 0) {
            LOG(INFO) << "mount succeeded: " << bits[1] << " " << options;
        } else {
            PLOG(FATAL) << "mount FAILED: " << bits[1] << " " << bits[3];
        }
    }

    const char* path = "/system/bin/init";
    const char* args[] = {path, "second_stage", nullptr};
    execv(path, const_cast<char**>(args));

    // execv() only returns if an error happened, in which case we
    // panic and never return from this function.
    PLOG(FATAL) << "execv(\"" << path << "\") failed";

    return 1;
}

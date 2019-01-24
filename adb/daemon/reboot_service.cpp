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

#define TRACE_TAG SERVICES

#include "sysdeps.h"

#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <string>

#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <bootloader_message/bootloader_message.h>
#include <cutils/android_reboot.h>

#include "adb_io.h"
#include "adb_unique_fd.h"

void reboot_service(unique_fd fd, const std::string& arg) {
    std::string reboot_arg = arg;
    sync();

    if (reboot_arg.empty()) reboot_arg = "adb";
    std::string reboot_string = android::base::StringPrintf("reboot,%s", reboot_arg.c_str());

    if (reboot_arg == "fastboot" &&
        android::base::GetBoolProperty("ro.boot.dynamic_partitions", false) &&
        access("/dev/socket/recovery", F_OK) == 0) {
        LOG(INFO) << "Recovery specific reboot fastboot";
        /*
         * The socket is created to allow switching between recovery and
         * fastboot.
         */
        android::base::unique_fd sock(socket(AF_UNIX, SOCK_STREAM, 0));
        if (sock < 0) {
            WriteFdFmt(fd, "reboot (%s) create\n", strerror(errno));
            PLOG(ERROR) << "Creating recovery socket failed";
            return;
        }

        sockaddr_un addr = {.sun_family = AF_UNIX};
        strncpy(addr.sun_path, "/dev/socket/recovery", sizeof(addr.sun_path) - 1);
        if (connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == -1) {
            WriteFdFmt(fd, "reboot (%s) connect\n", strerror(errno));
            PLOG(ERROR) << "Couldn't connect to recovery socket";
            return;
        }
        const char msg_switch_to_fastboot = 'f';
        auto ret = adb_write(sock, &msg_switch_to_fastboot, sizeof(msg_switch_to_fastboot));
        if (ret != sizeof(msg_switch_to_fastboot)) {
            WriteFdFmt(fd, "reboot (%s) write\n", strerror(errno));
            PLOG(ERROR) << "Couldn't write message to recovery socket to switch to fastboot";
            return;
        }
    } else {
        if (!android::base::SetProperty(ANDROID_RB_PROPERTY, reboot_string)) {
            WriteFdFmt(fd.get(), "reboot (%s) failed\n", reboot_string.c_str());
            return;
        }
    }
    // Don't return early. Give the reboot command time to take effect
    // to avoid messing up scripts which do "adb reboot && adb wait-for-device"
    while (true) {
        pause();
    }
}

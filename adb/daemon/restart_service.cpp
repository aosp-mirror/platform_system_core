/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include <unistd.h>

#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <log/log_properties.h>

#include "adb_io.h"
#include "adb_unique_fd.h"

void restart_root_service(unique_fd fd) {
    if (getuid() == 0) {
        WriteFdExactly(fd.get(), "adbd is already running as root\n");
        return;
    }
    if (!__android_log_is_debuggable()) {
        WriteFdExactly(fd.get(), "adbd cannot run as root in production builds\n");
        return;
    }

    LOG(INFO) << "adbd restarting as root";
    android::base::SetProperty("service.adb.root", "1");
    WriteFdExactly(fd.get(), "restarting adbd as root\n");
}

void restart_unroot_service(unique_fd fd) {
    if (getuid() != 0) {
        WriteFdExactly(fd.get(), "adbd not running as root\n");
        return;
    }

    LOG(INFO) << "adbd restarting as nonroot";
    android::base::SetProperty("service.adb.root", "0");
    WriteFdExactly(fd.get(), "restarting adbd as non root\n");
}

void restart_tcp_service(unique_fd fd, int port) {
    if (port <= 0) {
        WriteFdFmt(fd.get(), "invalid port %d\n", port);
        return;
    }

    LOG(INFO) << "adbd restarting in TCP mode (port = " << port << ")";
    android::base::SetProperty("service.adb.tcp.port", android::base::StringPrintf("%d", port));
    WriteFdFmt(fd.get(), "restarting in TCP mode port: %d\n", port);
}

void restart_usb_service(unique_fd fd) {
    LOG(INFO) << "adbd restarting in USB mode";
    android::base::SetProperty("service.adb.tcp.port", "0");
    WriteFdExactly(fd.get(), "restarting in USB mode\n");
}

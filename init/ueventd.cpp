/*
 * Copyright (C) 2010 The Android Open Source Project
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

#include "ueventd.h"

#include <ctype.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <selinux/selinux.h>

#include "devices.h"
#include "firmware_handler.h"
#include "log.h"
#include "uevent_listener.h"
#include "ueventd_parser.h"
#include "util.h"

DeviceHandler CreateDeviceHandler() {
    Parser parser;

    std::vector<Subsystem> subsystems;
    parser.AddSectionParser("subsystem", std::make_unique<SubsystemParser>(&subsystems));

    using namespace std::placeholders;
    std::vector<SysfsPermissions> sysfs_permissions;
    std::vector<Permissions> dev_permissions;
    parser.AddSingleLineParser(
        "/sys/", std::bind(ParsePermissionsLine, _1, _2, &sysfs_permissions, nullptr));
    parser.AddSingleLineParser("/dev/",
                               std::bind(ParsePermissionsLine, _1, _2, nullptr, &dev_permissions));

    parser.ParseConfig("/ueventd.rc");
    parser.ParseConfig("/vendor/ueventd.rc");
    parser.ParseConfig("/odm/ueventd.rc");

    /*
     * keep the current product name base configuration so
     * we remain backwards compatible and allow it to override
     * everything
     * TODO: cleanup platform ueventd.rc to remove vendor specific
     * device node entries (b/34968103)
     */
    std::string hardware = android::base::GetProperty("ro.hardware", "");
    parser.ParseConfig("/ueventd." + hardware + ".rc");

    return DeviceHandler(std::move(dev_permissions), std::move(sysfs_permissions),
                         std::move(subsystems));
}

int ueventd_main(int argc, char **argv)
{
    /*
     * init sets the umask to 077 for forked processes. We need to
     * create files with exact permissions, without modification by
     * the umask.
     */
    umask(000);

    /* Prevent fire-and-forget children from becoming zombies.
     * If we should need to wait() for some children in the future
     * (as opposed to none right now), double-forking here instead
     * of ignoring SIGCHLD may be the better solution.
     */
    signal(SIGCHLD, SIG_IGN);

    InitKernelLogging(argv);

    LOG(INFO) << "ueventd started!";

    selinux_callback cb;
    cb.func_log = selinux_klog_callback;
    selinux_set_callback(SELINUX_CB_LOG, cb);

    DeviceHandler device_handler = CreateDeviceHandler();
    UeventListener uevent_listener;

    if (access(COLDBOOT_DONE, F_OK) != 0) {
        Timer t;

        uevent_listener.RegenerateUevents([&device_handler](const Uevent& uevent) {
            HandleFirmwareEvent(uevent);
            device_handler.HandleDeviceEvent(uevent);
            return RegenerationAction::kContinue;
        });

        close(open(COLDBOOT_DONE, O_WRONLY | O_CREAT | O_CLOEXEC, 0000));
        LOG(INFO) << "Coldboot took " << t;
    }

    uevent_listener.DoPolling([&device_handler](const Uevent& uevent) {
        HandleFirmwareEvent(uevent);
        device_handler.HandleDeviceEvent(uevent);
    });

    return 0;
}

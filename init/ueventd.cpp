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
#include <grp.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <selinux/selinux.h>

#include "devices.h"
#include "log.h"
#include "ueventd_parser.h"
#include "util.h"

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

    ueventd_parse_config_file("/ueventd.rc");
    ueventd_parse_config_file("/vendor/ueventd.rc");
    ueventd_parse_config_file("/odm/ueventd.rc");

    /*
     * keep the current product name base configuration so
     * we remain backwards compatible and allow it to override
     * everything
     * TODO: cleanup platform ueventd.rc to remove vendor specific
     * device node entries (b/34968103)
     */
    std::string hardware = android::base::GetProperty("ro.hardware", "");
    ueventd_parse_config_file(android::base::StringPrintf("/ueventd.%s.rc", hardware.c_str()).c_str());

    device_init();

    pollfd ufd;
    ufd.events = POLLIN;
    ufd.fd = get_device_fd();

    while (true) {
        ufd.revents = 0;
        int nr = poll(&ufd, 1, -1);
        if (nr <= 0) {
            continue;
        }
        if (ufd.revents & POLLIN) {
            handle_device_fd();
        }
    }

    return 0;
}

void set_device_permission(const char* fn, int line, int nargs, char **args)
{
    char *name;
    char *attr = 0;
    mode_t perm;
    uid_t uid;
    gid_t gid;
    char *endptr;

    if (nargs == 0)
        return;

    if (args[0][0] == '#')
        return;

    name = args[0];

    if (!strncmp(name,"/sys/", 5) && (nargs == 5)) {
        LOG(INFO) << "/sys/ rule " << args[0] << " " << args[1];
        attr = args[1];
        args++;
        nargs--;
    }

    if (nargs != 4) {
        LOG(ERROR) << "invalid line (" << fn << ":" << line << ") line for '" << args[0] << "'";
        return;
    }

    perm = strtol(args[1], &endptr, 8);
    if (!endptr || *endptr != '\0') {
        LOG(ERROR) << "invalid mode (" << fn << ":" << line << ") '" << args[1] << "'";
        return;
    }

    struct passwd* pwd = getpwnam(args[2]);
    if (!pwd) {
        LOG(ERROR) << "invalid uid (" << fn << ":" << line << ") '" << args[2] << "'";
        return;
    }
    uid = pwd->pw_uid;

    struct group* grp = getgrnam(args[3]);
    if (!grp) {
        LOG(ERROR) << "invalid gid (" << fn << ":" << line << ") '" << args[3] << "'";
        return;
    }
    gid = grp->gr_gid;

    if (attr) {
        sysfs_permissions.emplace_back(name, attr, perm, uid, gid);
    } else {
        dev_permissions.emplace_back(name, perm, uid, gid);
    }
}

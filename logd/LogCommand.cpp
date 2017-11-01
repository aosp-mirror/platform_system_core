/*
 * Copyright (C) 2012-2014 The Android Open Source Project
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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <private/android_filesystem_config.h>

#include "LogCommand.h"
#include "LogUtils.h"

LogCommand::LogCommand(const char* cmd) : FrameworkCommand(cmd) {
}

// gets a list of supplementary group IDs associated with
// the socket peer.  This is implemented by opening
// /proc/PID/status and look for the "Group:" line.
//
// This function introduces races especially since status
// can change 'shape' while reading, the net result is err
// on lack of permission.
//
// Race-free alternative is to introduce pairs of sockets
// and threads for each command and reading, one each that
// has open permissions, and one that has restricted
// permissions.

static bool groupIsLog(char* buf) {
    char* ptr;
    static const char ws[] = " \n";

    for (buf = strtok_r(buf, ws, &ptr); buf; buf = strtok_r(NULL, ws, &ptr)) {
        errno = 0;
        gid_t Gid = strtol(buf, NULL, 10);
        if (errno != 0) {
            return false;
        }
        if (Gid == AID_LOG) {
            return true;
        }
    }
    return false;
}

bool clientHasLogCredentials(uid_t uid, gid_t gid, pid_t pid) {
    if ((uid == AID_ROOT) || (uid == AID_SYSTEM) || (uid == AID_LOG)) {
        return true;
    }

    if ((gid == AID_ROOT) || (gid == AID_SYSTEM) || (gid == AID_LOG)) {
        return true;
    }

    // FYI We will typically be here for 'adb logcat'
    char filename[256];
    snprintf(filename, sizeof(filename), "/proc/%u/status", pid);

    bool ret;
    bool foundLog = false;
    bool foundGid = false;
    bool foundUid = false;

    //
    // Reading /proc/<pid>/status is rife with race conditions. All of /proc
    // suffers from this and its use should be minimized. However, we have no
    // choice.
    //
    // Notably the content from one 4KB page to the next 4KB page can be from a
    // change in shape even if we are gracious enough to attempt to read
    // atomically. getline can not even guarantee a page read is not split up
    // and in effect can read from different vintages of the content.
    //
    // We are finding out in the field that a 'logcat -c' via adb occasionally
    // is returned with permission denied when we did only one pass and thus
    // breaking scripts. For security we still err on denying access if in
    // doubt, but we expect the falses  should be reduced significantly as
    // three times is a charm.
    //
    for (int retry = 3; !(ret = foundGid && foundUid && foundLog) && retry;
         --retry) {
        FILE* file = fopen(filename, "r");
        if (!file) {
            continue;
        }

        char* line = NULL;
        size_t len = 0;
        while (getline(&line, &len, file) > 0) {
            static const char groups_string[] = "Groups:\t";
            static const char uid_string[] = "Uid:\t";
            static const char gid_string[] = "Gid:\t";

            if (strncmp(groups_string, line, sizeof(groups_string) - 1) == 0) {
                if (groupIsLog(line + sizeof(groups_string) - 1)) {
                    foundLog = true;
                }
            } else if (strncmp(uid_string, line, sizeof(uid_string) - 1) == 0) {
                uid_t u[4] = { (uid_t)-1, (uid_t)-1, (uid_t)-1, (uid_t)-1 };

                sscanf(line + sizeof(uid_string) - 1, "%u\t%u\t%u\t%u", &u[0],
                       &u[1], &u[2], &u[3]);

                // Protect against PID reuse by checking that UID is the same
                if ((uid == u[0]) && (uid == u[1]) && (uid == u[2]) &&
                    (uid == u[3])) {
                    foundUid = true;
                }
            } else if (strncmp(gid_string, line, sizeof(gid_string) - 1) == 0) {
                gid_t g[4] = { (gid_t)-1, (gid_t)-1, (gid_t)-1, (gid_t)-1 };

                sscanf(line + sizeof(gid_string) - 1, "%u\t%u\t%u\t%u", &g[0],
                       &g[1], &g[2], &g[3]);

                // Protect against PID reuse by checking that GID is the same
                if ((gid == g[0]) && (gid == g[1]) && (gid == g[2]) &&
                    (gid == g[3])) {
                    foundGid = true;
                }
            }
        }
        free(line);
        fclose(file);
    }

    return ret;
}

bool clientHasLogCredentials(SocketClient* cli) {
    return clientHasLogCredentials(cli->getUid(), cli->getGid(), cli->getPid());
}

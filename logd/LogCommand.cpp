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

LogCommand::LogCommand(const char *cmd) : FrameworkCommand(cmd) {
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

static bool groupIsLog(char *buf) {
    char *ptr;
    static const char ws[] = " \n";
    bool ret = false;

    for (buf = strtok_r(buf, ws, &ptr); buf; buf = strtok_r(NULL, ws, &ptr)) {
        errno = 0;
        gid_t Gid = strtol(buf, NULL, 10);
        if (errno != 0) {
            return false;
        }
        if (Gid == AID_LOG) {
            ret = true;
        }
    }
    return ret;
}

bool clientHasLogCredentials(SocketClient * cli) {
    uid_t uid = cli->getUid();
    if (uid == AID_ROOT) {
        return true;
    }

    gid_t gid = cli->getGid();
    if ((gid == AID_ROOT) || (gid == AID_SYSTEM) || (gid == AID_LOG)) {
        return true;
    }

    // FYI We will typically be here for 'adb logcat'
    bool ret = false;

    char filename[1024];
    snprintf(filename, sizeof(filename), "/proc/%d/status", cli->getPid());

    FILE *file = fopen(filename, "r");
    if (!file) {
        return ret;
    }

    bool foundGid = false;
    bool foundUid = false;

    char line[1024];
    while (fgets(line, sizeof(line), file)) {
        static const char groups_string[] = "Groups:\t";
        static const char uid_string[] = "Uid:\t";
        static const char gid_string[] = "Gid:\t";

        if (strncmp(groups_string, line, strlen(groups_string)) == 0) {
            ret = groupIsLog(line + strlen(groups_string));
            if (!ret) {
                break;
            }
        } else if (strncmp(uid_string, line, strlen(uid_string)) == 0) {
            uid_t u[4] = { (uid_t) -1, (uid_t) -1, (uid_t) -1, (uid_t) -1};

            sscanf(line + strlen(uid_string), "%u\t%u\t%u\t%u",
                   &u[0], &u[1], &u[2], &u[3]);

            // Protect against PID reuse by checking that the UID is the same
            if ((uid != u[0]) || (uid != u[1]) || (uid != u[2]) || (uid != u[3])) {
                ret = false;
                break;
            }
            foundUid = true;
        } else if (strncmp(gid_string, line, strlen(gid_string)) == 0) {
            gid_t g[4] = { (gid_t) -1, (gid_t) -1, (gid_t) -1, (gid_t) -1};

            sscanf(line + strlen(gid_string), "%u\t%u\t%u\t%u",
                   &g[0], &g[1], &g[2], &g[3]);

            // Protect against PID reuse by checking that the GID is the same
            if ((gid != g[0]) || (gid != g[1]) || (gid != g[2]) || (gid != g[3])) {
                ret = false;
                break;
            }
            foundGid = true;
        }
    }

    fclose(file);

    if (!foundGid || !foundUid) {
        ret = false;
    }

    return ret;
}

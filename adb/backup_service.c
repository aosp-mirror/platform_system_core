/*
 * Copyright (C) 2011 The Android Open Source Project
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

#include <unistd.h>
#include <stdio.h>

#include "sysdeps.h"

#define TRACE_TAG  TRACE_ADB
#include "adb.h"

/* returns the data socket passing the backup data here for forwarding */
int backup_service(BackupOperation op, char* args) {
    pid_t pid;
    int s[2];
    char* operation;
    int socketnum;

    // Command string and choice of stdin/stdout for the pipe depend on our invocation
    if (op == BACKUP) {
        operation = "backup";
        socketnum = STDOUT_FILENO;
    } else {
        operation = "restore";
        socketnum = STDIN_FILENO;
    }

    D("backup_service(%s, %s)\n", operation, args);

    // set up the pipe from the subprocess to here
    // parent will read s[0]; child will write s[1]
    if (adb_socketpair(s)) {
        D("can't create backup/restore socketpair\n");
        fprintf(stderr, "unable to create backup/restore socketpair\n");
        return -1;
    }

    // spin off the child process to run the backup command
    pid = fork();
    if (pid < 0) {
        // failure
        D("can't fork for %s\n", operation);
        fprintf(stderr, "unable to fork for %s\n", operation);
        adb_close(s[0]);
        adb_close(s[1]);
        return -1;
    }

    // Great, we're off and running.
    if (pid == 0) {
        char* p;
        int argc;
        char** bu_args;

        // child -- actually run the backup here
        argc = 2; // room for the basic 'bu' argv[0] and '[operation]' argv[1]
        for (p = (char*)args; p && *p; ) {
            argc++;
            while (*p && *p != ':') p++;
            if (*p == ':') p++;
        }

        bu_args = (char**) alloca(argc*sizeof(char*) + 1);
        bu_args[0] = "bu";
        bu_args[1] = operation;
        argc = 2;   // run through again to build the argv array
        for (p = (char*)args; p && *p; ) {
            bu_args[argc++] = p;
            while (*p && *p != ':') p++;
            if (*p == ':') {
                *p = 0;
                p++;
            }
        }
        bu_args[argc] = NULL;

        // Close the half of the socket that we don't care about, route 'bu's console
        // to the output socket, and off we go
        adb_close(s[0]);
        dup2(s[1], socketnum);

        // off we go
        execvp("/system/bin/bu", (char * const *)bu_args);
        // oops error - close up shop and go home
        fprintf(stderr, "Unable to exec 'bu', bailing\n");
        exit(-1);
    } else {
        // parent, i.e. adbd -- close the sending half of the socket
        adb_close(s[1]);
    }

    // we'll be reading from s[0] as the data is sent by the child process
    return s[0];
}

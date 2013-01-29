/*
 * Copyright (C) 2008 The Android Open Source Project
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

#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>

#include <logwrap/logwrap.h>

#include "cutils/log.h"

void fatal(const char *msg) {
    fprintf(stderr, "%s", msg);
    ALOG(LOG_ERROR, "logwrapper", "%s", msg);
    exit(-1);
}

void usage() {
    fatal(
        "Usage: logwrapper [-d] BINARY [ARGS ...]\n"
        "\n"
        "Forks and executes BINARY ARGS, redirecting stdout and stderr to\n"
        "the Android logging system. Tag is set to BINARY, priority is\n"
        "always LOG_INFO.\n"
        "\n"
        "-d: Causes logwrapper to SIGSEGV when BINARY terminates\n"
        "    fault address is set to the status of wait()\n");
}

int main(int argc, char* argv[]) {
    int seg_fault_on_exit = 0;
    int status = 0xAAAA;
    int rc;

    if (argc < 2) {
        usage();
    }

    if (strncmp(argv[1], "-d", 2) == 0) {
        seg_fault_on_exit = 1;
        argc--;
        argv++;
    }

    if (argc < 2) {
        usage();
    }

    rc = android_fork_execvp(argc - 1, &argv[1], &status, true, true);
    if (!rc) {
        if (WIFEXITED(status))
            rc = WEXITSTATUS(status);
        else
            rc = -ECHILD;
    }

    if (seg_fault_on_exit) {
        *(int *)status = 0;  // causes SIGSEGV with fault_address = status
    }

    return rc;
}

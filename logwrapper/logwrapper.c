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

#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include "private/android_filesystem_config.h"
#include "cutils/log.h"

void fatal(const char *msg) {
    fprintf(stderr, "%s", msg);
    LOG(LOG_ERROR, "logwrapper", "%s", msg);
    exit(-1);
}

void usage() {
    fatal(
        "Usage: logwrapper [-x] BINARY [ARGS ...]\n"
        "\n"
        "Forks and executes BINARY ARGS, redirecting stdout and stderr to\n"
        "the Android logging system. Tag is set to BINARY, priority is\n"
        "always LOG_INFO.\n"
        "\n"
        "-x: Causes logwrapper to SIGSEGV when BINARY terminates\n"
        "    fault address is set to the status of wait()\n");
}

void parent(const char *tag, int seg_fault_on_exit, int parent_read) {
    int status;
    char buffer[4096];

    int a = 0;  // start index of unprocessed data
    int b = 0;  // end index of unprocessed data
    int sz;
    while ((sz = read(parent_read, &buffer[b], sizeof(buffer) - 1 - b)) > 0) {

        sz += b;
        // Log one line at a time
        for (b = 0; b < sz; b++) {
            if (buffer[b] == '\r') {
                buffer[b] = '\0';
            } else if (buffer[b] == '\n') {
                buffer[b] = '\0';
                LOG(LOG_INFO, tag, "%s", &buffer[a]);
                a = b + 1;
            }
        }

        if (a == 0 && b == sizeof(buffer) - 1) {
            // buffer is full, flush
            buffer[b] = '\0';
            LOG(LOG_INFO, tag, "%s", &buffer[a]);
            b = 0;
        } else if (a != b) {
            // Keep left-overs
            b -= a;
            memmove(buffer, &buffer[a], b);
            a = 0;
        } else {
            a = 0;
            b = 0;
        }

    }
    // Flush remaining data
    if (a != b) {
        buffer[b] = '\0';
	LOG(LOG_INFO, tag, "%s", &buffer[a]);
    }
    status = 0xAAAA;
    if (wait(&status) != -1) {  // Wait for child
        if (WIFEXITED(status))
            LOG(LOG_INFO, "logwrapper", "%s terminated by exit(%d)", tag,
                    WEXITSTATUS(status));
        else if (WIFSIGNALED(status))
            LOG(LOG_INFO, "logwrapper", "%s terminated by signal %d", tag,
                    WTERMSIG(status));
        else if (WIFSTOPPED(status))
            LOG(LOG_INFO, "logwrapper", "%s stopped by signal %d", tag,
                    WSTOPSIG(status));
    } else
        LOG(LOG_INFO, "logwrapper", "%s wait() failed: %s (%d)", tag,
                strerror(errno), errno);
    if (seg_fault_on_exit)
        *(int *)status = 0;  // causes SIGSEGV with fault_address = status
}

void child(int argc, char* argv[]) {
    // create null terminated argv_child array
    char* argv_child[argc + 1];
    memcpy(argv_child, argv, argc * sizeof(char *));
    argv_child[argc] = NULL;

    if (execvp(argv_child[0], argv_child)) {
        LOG(LOG_ERROR, "logwrapper",
            "executing %s failed: %s\n", argv_child[0], strerror(errno));
        exit(-1);
    }
}

int main(int argc, char* argv[]) {
    pid_t pid;
    int seg_fault_on_exit = 0;

    int parent_ptty;
    int child_ptty;
    char *child_devname = NULL;

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

    /* Use ptty instead of socketpair so that STDOUT is not buffered */
    parent_ptty = open("/dev/ptmx", O_RDWR);
    if (parent_ptty < 0) {
        fatal("Cannot create parent ptty\n");
    }

    if (grantpt(parent_ptty) || unlockpt(parent_ptty) ||
            ((child_devname = (char*)ptsname(parent_ptty)) == 0)) {
        fatal("Problem with /dev/ptmx\n");
    }

    pid = fork();
    if (pid < 0) {
        fatal("Failed to fork\n");
    } else if (pid == 0) {
        child_ptty = open(child_devname, O_RDWR);
        if (child_ptty < 0) {
            fatal("Problem with child ptty\n");
        }

        // redirect stdout and stderr
        close(parent_ptty);
        dup2(child_ptty, 1);
        dup2(child_ptty, 2);
        close(child_ptty);

        child(argc - 1, &argv[1]);

    } else {
        // switch user and group to "log"
        // this may fail if we are not root, 
        // but in that case switching user/group is unnecessary 
        setgid(AID_LOG);
        setuid(AID_LOG);

        parent(argv[1], seg_fault_on_exit, parent_ptty);
    }

    return 0;
}

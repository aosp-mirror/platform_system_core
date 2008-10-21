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

#include "cutils/log.h"

void fatal(const char *msg) {
    fprintf(stderr, msg);
    LOG(LOG_ERROR, "logwrapper", msg);
    exit(-1);
}

void usage() {
    fatal(
        "Usage: logwrapper BINARY [ARGS ...]\n"
        "\n"
        "Forks and executes BINARY ARGS, redirecting stdout and stderr to\n"
        "the Android logging system. Tag is set to BINARY, priority is\n"
        "always LOG_INFO.\n");
}

void parent(const char *tag, int parent_read) {
    int status;
    char buffer[1024];

    int a = 0;  // start index of unprocessed data
    int b = 0;  // end index of unprocessed data
    int sz;
    while ((sz = read(parent_read, &buffer[b], 1023 - b)) > 0) {
        // Log one line at a time
        for (b = a; b < sz; b++) {
            if (buffer[b] == '\n') {
                buffer[b] = '\0';
                LOG(LOG_INFO, tag, &buffer[a]);
                a = b + 1;
            }
        }

        if (a == 0 && b == 1023) {
            // buffer is full, flush
            buffer[b] = '\0';
            LOG(LOG_INFO, tag, &buffer[a]);
            b = 0;
        } else {
            // Keep left-overs
            b = sz - a;
            memmove(buffer, &buffer[a], b);
            a = 0;
        }
    }
    // Flush remaining data
    if (a != b) {
        buffer[b] = '\0';
        LOG(LOG_INFO, tag, &buffer[a]);
    }
    wait(&status);  // Wait for child
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

    int pipe_fds[2];
    int *parent_read = &pipe_fds[0];
    int *child_write = &pipe_fds[1];

    if (argc < 2) {
        usage();
    }

    if (pipe(pipe_fds) < 0) {
        fatal("Cannot create pipe\n");
    }

    pid = fork();
    if (pid < 0) {
        fatal("Failed to fork\n");
    } else if (pid == 0) {
        // redirect stdout and stderr
        close(*parent_read);
        dup2(*child_write, 1);
        dup2(*child_write, 2);
        close(*child_write);

        child(argc - 1, &argv[1]);

    } else {
        close(*child_write);

        parent(argv[1], *parent_read);
    }

    return 0;
}

/*
 * Copyright (c) 2014, The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *  * Neither the name of Google, Inc. nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

static int print_usage() {
    fprintf(stderr, "mknod <path> [b|c|u|p] <major> <minor>\n");
    return EXIT_FAILURE;
}

int mknod_main(int argc, char **argv) {
    char *path = NULL;
    int major = 0;
    int minor = 0;
    int args = 0;
    mode_t mode = 0660;

    /* Check correct argument count is 3 or 5 */
    if (argc != 3 && argc != 5) {
        fprintf(stderr, "Incorrect argument count\n");
        return print_usage();
    }

    path = argv[1];

    const char node_type = *argv[2];
    switch (node_type) {
    case 'b':
        mode |= S_IFBLK;
        args = 5;
        break;
    case 'c':
    case 'u':
        mode |= S_IFCHR;
        args = 5;
        break;
    case 'p':
        mode |= S_IFIFO;
        args = 3;
        break;
    default:
        fprintf(stderr, "Invalid node type '%c'\n", node_type);
        return print_usage();
    }

    if (argc != args) {
        if (args == 5) {
            fprintf(stderr, "Node type '%c' requires <major> and <minor>\n", node_type);
        } else {
            fprintf(stderr, "Node type '%c' does not require <major> and <minor>\n", node_type);
        }
        return print_usage();
    }

    if (args == 5) {
        major = atoi(argv[3]);
        minor = atoi(argv[4]);
    }

    if (mknod(path, mode, makedev(major, minor))) {
        perror("Unable to create node");
        return EXIT_FAILURE;
    }
    return 0;
}

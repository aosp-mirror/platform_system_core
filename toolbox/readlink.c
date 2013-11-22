/*
 * Copyright (c) 2013, The Android Open Source Project
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

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static int skip_newline, quiet_errors, canonicalize;

static void usage(char* name) {
    fprintf(stderr, "Usage: %s [OPTION]... FILE\n", name);
}

int readlink_main(int argc, char* argv[]) {
    int c;
    while ((c = getopt(argc, argv, "nfqs")) != -1) {
        switch (c) {
        case 'n':
            skip_newline = 1;
            break;
        case 'f':
            canonicalize = 1;
            break;
        case 'q':
        case 's':
            quiet_errors = 1;
            break;
        case '?':
        default:
            usage(argv[0]);
            return EXIT_FAILURE;
        }
    }
    int index = optind;
    if (argc - index != 1) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    char name[PATH_MAX+1];
    if (canonicalize) {
        if(!realpath(argv[optind], name)) {
            if (!quiet_errors) {
                perror("readlink");
            }
            return EXIT_FAILURE;
        }
    } else {
        ssize_t len = readlink(argv[1], name, PATH_MAX);

        if (len < 0) {
            if (!quiet_errors) {
                perror("readlink");
            }
            return EXIT_FAILURE;
        }
        name[len] = '\0';
    }

    fputs(name, stdout);
    if (!skip_newline) {
        fputs("\n", stdout);
    }

    return EXIT_SUCCESS;
}

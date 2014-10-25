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
#include <unistd.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/resource.h>

static void
usage(const char *s)
{
    fprintf(stderr, "usage: %s pid resource cur max\n", s);
    exit(EXIT_FAILURE);
}

int prlimit_main(int argc, char *argv[])
{
    pid_t pid;
    struct rlimit64 rl;
    int resource;
    int rc;

    if (argc != 5)
        usage(*argv);

    if (sscanf(argv[1], "%d", &pid) != 1)
        usage(*argv);

    if (sscanf(argv[2], "%d", &resource) != 1)
        usage(*argv);

    if (sscanf(argv[3], "%llu", &rl.rlim_cur) != 1)
        usage(*argv);

    if (sscanf(argv[4], "%llu", &rl.rlim_max) != 1)
        usage(*argv);

    printf("setting resource %d of pid %d to [%llu,%llu]\n", resource, pid,
            rl.rlim_cur, rl.rlim_max);
    rc = prlimit64(pid, resource, &rl, NULL);
    if (rc < 0) {
        perror("prlimit");
        exit(EXIT_FAILURE);
    }

    return 0;
}

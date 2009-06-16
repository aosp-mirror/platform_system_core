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
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>

#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>

#include <cutils/sockets.h>
#include <private/android_filesystem_config.h>

static void usage(char *progname);
static int do_monitor(int sock, int stop_after_cmd);
static int do_cmd(int sock, int argc, char **argv);

int main(int argc, char **argv) {
    int sock;

    if (argc < 2)
        usage(argv[0]);

    if ((sock = socket_local_client("nexus",
                                     ANDROID_SOCKET_NAMESPACE_RESERVED,
                                     SOCK_STREAM)) < 0) {
        fprintf(stderr, "Error connecting (%s)\n", strerror(errno));
        exit(4);
    }

    if (!strcmp(argv[1], "monitor"))
        exit(do_monitor(sock, 0));
    exit(do_cmd(sock, argc, argv));
}

static int do_cmd(int sock, int argc, char **argv) {
    char final_cmd[255] = { '\0' };
    int i;

    for (i = 1; i < argc; i++) {
        char *cmp;

        if (!index(argv[i], ' '))
            asprintf(&cmp, "%s%s", argv[i], (i == (argc -1)) ? "" : " ");
        else
            asprintf(&cmp, "\"%s\"%s", argv[i], (i == (argc -1)) ? "" : " ");

        strcat(final_cmd, cmp);
        free(cmp);
    }

    if (write(sock, final_cmd, strlen(final_cmd) + 1) < 0) {
        perror("write");
        return errno;
    }

    return do_monitor(sock, 1);
}

static int do_monitor(int sock, int stop_after_cmd) {
    char *buffer = malloc(4096);

    if (!stop_after_cmd)
        printf("[Connected to Nexus]\n");

    while(1) {
        fd_set read_fds;
        struct timeval to;
        int rc = 0;

        to.tv_sec = 10;
        to.tv_usec = 0;

        FD_ZERO(&read_fds);
        FD_SET(sock, &read_fds);

        if ((rc = select(sock +1, &read_fds, NULL, NULL, &to)) < 0) {
            fprintf(stderr, "Error in select (%s)\n", strerror(errno));
            free(buffer);
            return errno;
        } else if (!rc) {
            continue;
            fprintf(stderr, "[TIMEOUT]\n");
            return ETIMEDOUT;
        } else if (FD_ISSET(sock, &read_fds)) {
            memset(buffer, 0, 4096);
            if ((rc = read(sock, buffer, 4096)) <= 0) {
                if (rc == 0)
                    fprintf(stderr, "Lost connection to Nexus - did it crash?\n");
                else
                    fprintf(stderr, "Error reading data (%s)\n", strerror(errno));
                free(buffer);
                if (rc == 0)
                    return ECONNRESET;
                return errno;
            }
            
            int offset = 0;
            int i = 0;

            for (i = 0; i < rc; i++) {
                if (buffer[i] == '\0') {
                    int code;
                    char tmp[4];

                    strncpy(tmp, buffer + offset, 3);
                    tmp[3] = '\0';
                    code = atoi(tmp);

                    printf("%s\n", buffer + offset);
                    if (stop_after_cmd) {
                        if (code >= 200 && code < 600)
                            return 0;
                    }
                    offset = i + 1;
                }
            }
        }
    }
    free(buffer);
    return 0;
}

static void usage(char *progname) {
    fprintf(stderr, "Usage: %s <monitor>|<cmd> [arg1] [arg2...]\n", progname);
    exit(1);
}


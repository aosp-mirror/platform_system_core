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

int main(int argc, char **argv) {
    int sock;

    if ((sock = socket_local_client("nexus",
                                     ANDROID_SOCKET_NAMESPACE_RESERVED,
                                     SOCK_STREAM)) < 0) {
        fprintf(stderr, "Error connecting (%s)\n", strerror(errno));
        exit(1);
    }

    printf("Connected to nexus\n");

    char line[255];
    char *buffer = malloc(4096);
    int cursor = 0;
    int col = 0;

    while(1) {
        fd_set read_fds;
        struct timeval to;
        int rc = 0;

        to.tv_sec = 10;
        to.tv_usec = 0;

        FD_ZERO(&read_fds);
        FD_SET(sock, &read_fds);
        FD_SET(0, &read_fds);

        if (col == 0) {
            fprintf(stdout, "-> ");
            fflush(stdout);
            col = 3;
        }
    
        if ((rc = select(sock +1, &read_fds, NULL, NULL, &to)) < 0) {
            fprintf(stderr, "Error in select (%s)\n", strerror(errno));
            exit(2);
        } else if (!rc) {
            continue;
        } else if (FD_ISSET(sock, &read_fds)) {
            memset(buffer, 0, 4096);
            if ((rc = read(sock, buffer, 4096)) <= 0) {
                 fprintf(stderr, "Error reading response (%s)\n", strerror(errno));
                 exit(2);
            }
            int i;
            for (i = 0; i < col; i++) {
                fprintf(stdout, "%c", 8);
            }

            printf("%s", buffer);
            printf("-> ");
            for (i = 0; i < cursor; i++) {
                fprintf(stdout, "%c", line[i]);
            }
            fflush(stdout);
        } else if (FD_ISSET(0, &read_fds)) {
            char c;

            if ((rc = read(0, &c, 1)) < 0) {
                fprintf(stderr, "Error reading from terminal (%s)\n", strerror(errno));
                exit(2);
            } else if (!rc) {
                fprintf(stderr, "0 length read from terminal\n");
                exit(2);
            }

            fprintf(stdout, "%c", c);
            fflush(stdout);

            line[cursor] = c;

            if (c == '\n') {
                if ((rc = write(sock, line, strlen(line))) < 0) {
                    fprintf(stderr, "Error writing to nexus (%s)\n", strerror(errno));
                    exit(2);
                }
                memset(line, 0, sizeof(line));
                cursor = 0;
                col = 0;
            } else {
                cursor++;
                col++;
            }
        }
    }

    exit(0);
}

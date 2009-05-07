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

static void signal_handler(int sig) {
    fprintf(stdout, "{ interrupt! }\n");
}

int main(int argc, char **argv) {
    int sock;

    if ((sock = socket_local_client("nexus",
                                     ANDROID_SOCKET_NAMESPACE_RESERVED,
                                     SOCK_STREAM)) < 0) {
        fprintf(stderr, "Error connecting (%s)\n", strerror(errno));
        exit(1);
    }

    printf("Connected to nexus\n");

    while(1) {
        fd_set read_fds;
        struct timeval to;
        int rc = 0;

        signal(SIGINT, SIG_DFL);

        printf("-> ");
        fflush(stdout);

        char buffer[255];
        if (!fgets(buffer, sizeof(buffer) -1, stdin)) {
            printf("Exiting...\n");
            exit(0);
        }

        buffer[strlen(buffer) -1] = 0;

        if (write(sock, buffer, strlen(buffer) +1) < 0) {
            fprintf(stderr, "Error writing data (%s)\n", strerror(errno));
            exit(2);
        }

wait:
        to.tv_sec = 10;
        to.tv_usec = 0;
        FD_ZERO(&read_fds);
        FD_SET(sock, &read_fds);
    
        signal(SIGINT, signal_handler);
     
        if ((rc = select(sock +1, &read_fds, NULL, NULL, &to)) < 0) {
            if (errno == EINTR)
                continue;
            fprintf(stderr, "Error in select (%s)\n", strerror(errno));
            exit(2);
        } else if (!rc) {
            printf("{response timeout}\n");
            continue;
        } else if (FD_ISSET(sock, &read_fds)) {
             if ((rc = read(sock, buffer, sizeof(buffer)-1)) <= 0) {
                 fprintf(stderr, "Error reading response (%s)\n", strerror(errno));
                 exit(2);
             }
            printf(" %s\n", buffer);
            goto wait;
        }
    }


    exit(0);

}

/*
 * Copyright (C) 2012 The Android Open Source Project
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

#include <stdlib.h>
#include <unistd.h>

#include <cutils/debugger.h>
#include <cutils/sockets.h>

int dump_tombstone(pid_t tid, char* pathbuf, size_t pathlen) {
    int s = socket_local_client(DEBUGGER_SOCKET_NAME,
            ANDROID_SOCKET_NAMESPACE_ABSTRACT, SOCK_STREAM);
    if (s < 0) {
        return -1;
    }

    debugger_msg_t msg;
    msg.tid = tid;
    msg.action = DEBUGGER_ACTION_DUMP_TOMBSTONE;

    int result = 0;
    if (TEMP_FAILURE_RETRY(write(s, &msg, sizeof(msg))) != sizeof(msg)) {
        result = -1;
    } else {
        char ack;
        if (TEMP_FAILURE_RETRY(read(s, &ack, 1)) != 1) {
            result = -1;
        } else {
            if (pathbuf && pathlen) {
                ssize_t n = TEMP_FAILURE_RETRY(read(s, pathbuf, pathlen - 1));
                if (n <= 0) {
                    result = -1;
                } else {
                    pathbuf[n] = '\0';
                }
            }
        }
    }
    TEMP_FAILURE_RETRY(close(s));
    return result;
}

int dump_backtrace_to_file(pid_t tid, int fd) {
    int s = socket_local_client(DEBUGGER_SOCKET_NAME,
            ANDROID_SOCKET_NAMESPACE_ABSTRACT, SOCK_STREAM);
    if (s < 0) {
        return -1;
    }

    debugger_msg_t msg;
    msg.tid = tid;
    msg.action = DEBUGGER_ACTION_DUMP_BACKTRACE;

    int result = 0;
    if (TEMP_FAILURE_RETRY(write(s, &msg, sizeof(msg))) != sizeof(msg)) {
        result = -1;
    } else {
        char ack;
        if (TEMP_FAILURE_RETRY(read(s, &ack, 1)) != 1) {
            result = -1;
        } else {
            char buffer[4096];
            ssize_t n;
            while ((n = TEMP_FAILURE_RETRY(read(s, buffer, sizeof(buffer)))) > 0) {
                if (TEMP_FAILURE_RETRY(write(fd, buffer, n)) != n) {
                    result = -1;
                    break;
                }
            }
        }
    }
    TEMP_FAILURE_RETRY(close(s));
    return result;
}

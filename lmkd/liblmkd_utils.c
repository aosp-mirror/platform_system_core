/*
 *  Copyright 2018 Google, Inc
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <errno.h>
#include <fcntl.h>
#include <sys/cdefs.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>

#include <liblmkd_utils.h>
#include <cutils/sockets.h>

int lmkd_connect() {
    return socket_local_client("lmkd",
                               ANDROID_SOCKET_NAMESPACE_RESERVED,
                               SOCK_SEQPACKET);
}

int lmkd_register_proc(int sock, struct lmk_procprio *params) {
    LMKD_CTRL_PACKET packet;
    size_t size;
    int ret;

    size = lmkd_pack_set_procprio(packet, params);
    ret = TEMP_FAILURE_RETRY(write(sock, packet, size));

    return (ret < 0) ? -1 : 0;
}

int create_memcg(uid_t uid, pid_t pid) {
    char buf[256];
    int tasks_file;
    int written;

    snprintf(buf, sizeof(buf), "/dev/memcg/apps/uid_%u", uid);
    if (mkdir(buf, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) < 0 &&
        errno != EEXIST) {
        return -1;
    }

    snprintf(buf, sizeof(buf), "/dev/memcg/apps/uid_%u/pid_%u", uid, pid);
    if (mkdir(buf, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) < 0 &&
        errno != EEXIST) {
        return -1;
    }

    snprintf(buf, sizeof(buf), "/dev/memcg/apps/uid_%u/pid_%u/tasks", uid, pid);
    tasks_file = open(buf, O_WRONLY);
    if (tasks_file < 0) {
        return -2;
    }
    written = snprintf(buf, sizeof(buf), "%u", pid);
    if (__predict_false(written >= (int)sizeof(buf))) {
        written = sizeof(buf) - 1;
    }
    written = TEMP_FAILURE_RETRY(write(tasks_file, buf, written));
    close(tasks_file);

    return (written < 0) ? -3 : 0;
}


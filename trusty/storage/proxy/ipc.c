/*
 * Copyright (C) 2016 The Android Open Source Project
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
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

#include <trusty/tipc.h>

#include "ipc.h"
#include "log.h"

#define MAX_RECONNECT_RETRY_COUNT 5
#define TRUSTY_RECONNECT_TIMEOUT_SEC 5

static int tipc_fd = -1;

int ipc_connect(const char *device, const char *port)
{
    int rc;
    uint retry_cnt = 0;

    assert(tipc_fd == -1);

    while(true) {
        rc = tipc_connect(device, port);
        if (rc >= 0)
            break;

        ALOGE("failed (%d) to connect to storage server\n", rc);
        if (++retry_cnt > MAX_RECONNECT_RETRY_COUNT) {
            ALOGE("max number of reconnect retries (%d) has been reached\n",
                   retry_cnt);
            return -1;
        }
        sleep(TRUSTY_RECONNECT_TIMEOUT_SEC);
    }
    tipc_fd = rc;
    return 0;
}

void ipc_disconnect(void)
{
    assert(tipc_fd >=  0);

    tipc_close(tipc_fd);
    tipc_fd = -1;
}

ssize_t ipc_get_msg(struct storage_msg *msg, void *req_buf, size_t req_buf_len)
{
    ssize_t rc;
    struct iovec iovs[2] = {{msg, sizeof(*msg)}, {req_buf, req_buf_len}};

    assert(tipc_fd >=  0);

    rc = readv(tipc_fd, iovs, 2);
    if (rc < 0) {
        ALOGE("failed to read request: %s\n", strerror(errno));
        return rc;
    }

   /* check for minimum size */
   if ((size_t)rc < sizeof(*msg)) {
       ALOGE("message is too short (%zu bytes received)\n", rc);
       return -1;
   }

   /* check for message completeness */
   if (msg->size != (uint32_t)rc) {
       ALOGE("inconsistent message size [cmd=%d] (%u != %u)\n",
             msg->cmd, msg->size, (uint32_t)rc);
       return -1;
   }

   return rc - sizeof(*msg);
}

int ipc_respond(struct storage_msg *msg, void *out, size_t out_size)
{
    ssize_t rc;
    struct iovec iovs[2] = {{msg, sizeof(*msg)}, {out, out_size}};

    assert(tipc_fd >=  0);

    msg->cmd |= STORAGE_RESP_BIT;

    rc = writev(tipc_fd, iovs, out ? 2 : 1);
    if (rc < 0) {
        ALOGE("error sending response 0x%x: %s\n",
              msg->cmd, strerror(errno));
        return -1;
    }

    return 0;
}



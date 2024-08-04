/*
 * Copyright (C) 2015 The Android Open Source Project
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

#define LOG_TAG "TrustyGateKeeper"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <log/log.h>
#include <trusty/tipc.h>

#include "trusty_gatekeeper_ipc.h"
#include "gatekeeper_ipc.h"

static const char* trusty_device_name = "/dev/trusty-ipc-dev0";
static int handle_ = 0;

void trusty_gatekeeper_set_dev_name(const char* device_name) {
    trusty_device_name = device_name;
}

int trusty_gatekeeper_connect() {
    int rc = tipc_connect(trusty_device_name, GATEKEEPER_PORT);
    if (rc < 0) {
        return rc;
    }

    handle_ = rc;
    return 0;
}

int trusty_gatekeeper_call(uint32_t cmd, void *in, uint32_t in_size, uint8_t *out,
                           uint32_t *out_size) {
    if (handle_ == 0) {
        ALOGE("not connected\n");
        return -EINVAL;
    }

    size_t msg_size = in_size + sizeof(struct gatekeeper_message);
    struct gatekeeper_message *msg = malloc(msg_size);
    msg->cmd = cmd;
    memcpy(msg->payload, in, in_size);

    ssize_t rc = write(handle_, msg, msg_size);
    free(msg);

    if (rc < 0) {
        ALOGE("failed to send cmd (%d) to %s: %s\n", cmd,
                GATEKEEPER_PORT, strerror(errno));
        return -errno;
    }

    rc = read(handle_, out, *out_size);
    if (rc < 0) {
        ALOGE("failed to retrieve response for cmd (%d) to %s: %s\n",
                cmd, GATEKEEPER_PORT, strerror(errno));
        return -errno;
    }

    if ((size_t) rc < sizeof(struct gatekeeper_message)) {
        ALOGE("invalid response size (%d)\n", (int) rc);
        return -EINVAL;
    }

    msg = (struct gatekeeper_message *) out;

    if ((cmd | GK_RESP_BIT) != msg->cmd) {
        ALOGE("invalid command (%d)\n", msg->cmd);
        return -EINVAL;
    }

    *out_size = ((size_t) rc) - sizeof(struct gatekeeper_message);
    return rc;
}

void trusty_gatekeeper_disconnect() {
    if (handle_ != 0) {
        tipc_close(handle_);
    }
}


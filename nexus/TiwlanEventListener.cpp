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

#include <errno.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/types.h>
#include <sys/socket.h>

#define LOG_TAG "TiwlanEventListener"
#include <cutils/log.h>

#include "TiwlanEventListener.h"

TiwlanEventListener::TiwlanEventListener(int socket) :
                     SocketListener(socket, false) {
}

bool TiwlanEventListener::onDataAvailable(SocketClient *cli) {
    struct ipc_ev_data *data;

    if (!(data = (struct ipc_ev_data *) malloc(sizeof(struct ipc_ev_data)))) {
        LOGE("Failed to allocate packet (out of memory)");
        return true;
    }

    if (recv(cli->getSocket(), data, sizeof(struct ipc_ev_data), 0) < 0) {
       LOGE("recv failed (%s)", strerror(errno));
       goto out;
    }

    if (data->event_type == IPC_EVENT_LINK_SPEED) {
        uint32_t *spd = (uint32_t *) data->buffer;
        *spd /= 2;
//        LOGD("Link speed = %u MB/s", *spd);
    } else if (data->event_type == IPC_EVENT_LOW_SNR) {
        LOGW("Low signal/noise ratio");
    } else if (data->event_type == IPC_EVENT_LOW_RSSI) {
        LOGW("Low RSSI");
    } else {
//        LOGD("Dropping unhandled driver event %d", data->event_type);
    }

    // TODO: Tell WifiController about the event
out:
    free(data);
    return true;
}

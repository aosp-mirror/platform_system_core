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

#ifndef _TIWLAN_EVENT_LISTENER_H__
#define _TIWLAN_EVENT_LISTENER_H__

#include <sysutils/SocketListener.h>

struct wpa_ctrl;
class SocketClient;
class ITiwlanEventHandler;
class TiwlanEventFactory;

class TiwlanEventListener: public SocketListener {
    
public:
    TiwlanEventListener(int sock);
    virtual ~TiwlanEventListener() {}

protected:
    virtual bool onDataAvailable(SocketClient *c);
};

// TODO: Move all this crap into a factory
#define TI_DRIVER_MSG_PORT 9001

#define IPC_EVENT_LINK_SPEED  2
#define IPC_EVENT_LOW_SNR     13
#define IPC_EVENT_LOW_RSSI    14

struct ipc_ev_data {
    uint32_t event_type;
    void     *event_id;
    uint32_t process_id;
    uint32_t delivery_type;
    uint32_t user_param;
    void     *event_callback;
    uint32_t bufferSize;
    uint8_t  buffer[2048];
};

#endif

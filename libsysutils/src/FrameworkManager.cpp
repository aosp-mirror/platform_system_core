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
#include <errno.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>

#include <cutils/config_utils.h>
#include <cutils/cpu_info.h>
#include <cutils/properties.h>
#include <cutils/sockets.h>

#define LOG_TAG "FrameworkManager"
#include <cutils/log.h>

#include <sysutils/FrameworkManager.h>
#include <sysutils/FrameworkListener.h>

FrameworkManager::FrameworkManager(FrameworkListener *Listener) {
    mDoorbell = -1;
    mFwSock = -1;
    mListener = Listener;

    pthread_mutex_init(&mWriteMutex, NULL);
}

int FrameworkManager::run() {

    if (mListener->run()) {
        LOGE("Error running listener (%s)", strerror(errno));
        return -1;
    }

    return 0;
}

/* ========
 * Privates
 * ========
 */

int FrameworkManager::sendMsg(char *msg) {
    LOGD("FrameworkManager::sendMsg(%s)", msg);
    if (mFwSock < 0) {
        errno = EHOSTUNREACH;
        return -1;
    }

    pthread_mutex_lock(&mWriteMutex);
    if (write(mFwSock, msg, strlen(msg) +1) < 0) {
        LOGW("Unable to send msg '%s' (%s)", msg, strerror(errno));
    }
    pthread_mutex_unlock(&mWriteMutex);
    return 0;
}

int FrameworkManager::sendMsg(char *msg, char *data) {
    char *buffer = (char *) alloca(strlen(msg) + strlen(data) + 1);
    if (!buffer) {
        errno = -ENOMEM;
        return -1;
    }
    strcpy(buffer, msg);
    strcat(buffer, data);
    return sendMsg(buffer);
}

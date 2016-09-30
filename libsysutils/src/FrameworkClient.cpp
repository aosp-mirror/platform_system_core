/*
 * Copyright (C) 2009-2016 The Android Open Source Project
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

#define LOG_TAG "FrameworkClient"

#include <alloca.h>
#include <errno.h>
#include <pthread.h>
#include <sys/types.h>

#include <android/log.h>
#include <sysutils/FrameworkClient.h>

FrameworkClient::FrameworkClient(int socket) {
    mSocket = socket;
    pthread_mutex_init(&mWriteMutex, NULL);
}

int FrameworkClient::sendMsg(const char *msg) {
    int ret;
    if (mSocket < 0) {
        errno = EHOSTUNREACH;
        return -1;
    }

    pthread_mutex_lock(&mWriteMutex);
    ret = TEMP_FAILURE_RETRY(write(mSocket, msg, strlen(msg) +1));
    if (ret < 0) {
        SLOGW("Unable to send msg '%s' (%s)", msg, strerror(errno));
    }
    pthread_mutex_unlock(&mWriteMutex);
    return 0;
}

int FrameworkClient::sendMsg(const char *msg, const char *data) {
    size_t bufflen = strlen(msg) + strlen(data) + 1;
    char *buffer = (char *) alloca(bufflen);
    if (!buffer) {
        errno = -ENOMEM;
        return -1;
    }
    snprintf(buffer, bufflen, "%s%s", msg, data);
    return sendMsg(buffer);
}


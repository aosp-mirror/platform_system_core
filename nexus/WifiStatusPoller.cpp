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

#define LOG_TAG "WifiStatusPoller"
#include <cutils/log.h>

#include "WifiStatusPoller.h"
#include "IWifiStatusPollerHandler.h"


WifiStatusPoller::WifiStatusPoller(IWifiStatusPollerHandler *handler) :
                  mHandlers(handler) {
    mPollingInterval = 5;
    mStarted = false;
}

int WifiStatusPoller::start() {

    if (pipe(mCtrlPipe))
        return -1;

    if (pthread_create(&mThread, NULL, WifiStatusPoller::threadStart, this))
        return -1;

    return 0;
}

int WifiStatusPoller::stop() {
    char c = 0;

    if (write(mCtrlPipe[1], &c, 1) != 1) {
        LOGE("Error writing to control pipe (%s)", strerror(errno));
        return -1;
    }

    void *ret;
    if (pthread_join(mThread, &ret)) {
        LOGE("Error joining to listener thread (%s)", strerror(errno));
        return -1;
    }
    close(mCtrlPipe[0]);
    close(mCtrlPipe[1]);
    return 0;
}

void *WifiStatusPoller::threadStart(void *obj) {
    WifiStatusPoller *me = reinterpret_cast<WifiStatusPoller *>(obj);

    me->mStarted = true;
    LOGD("Starting");
    me->run();
    me->mStarted = false;
    LOGD("Stopping");
    pthread_exit(NULL);
    return NULL;
}

void WifiStatusPoller::run() {

    while(1) {
        struct timeval to;
        fd_set read_fds;
        int rc = 0;
        int max = 0;

        FD_ZERO(&read_fds);
        to.tv_usec = 0;
        to.tv_sec = mPollingInterval;

        FD_SET(mCtrlPipe[0], &read_fds);
        max = mCtrlPipe[0];

        if ((rc = select(max + 1, &read_fds, NULL, NULL, &to)) < 0) {
            LOGE("select failed (%s)", strerror(errno));
            sleep(1);
            continue;
        } else if (!rc) {
            mHandlers->onStatusPollInterval();
        }
        if (FD_ISSET(mCtrlPipe[0], &read_fds))
            break;
    }
}

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
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>

#define LOG_TAG "DhcpClient"
#include <cutils/log.h>
#include <cutils/properties.h>

#include <sysutils/ServiceManager.h>

#include <netutils/ifc.h>
#include <netutils/dhcp.h>

#include "DhcpClient.h"
#include "DhcpState.h"
#include "DhcpListener.h"
#include "IDhcpEventHandlers.h"
#include "Controller.h"

DhcpClient::DhcpClient(IDhcpEventHandlers *handlers) :
            mState(DhcpState::INIT), mHandlers(handlers) {
    mServiceManager = new ServiceManager();
    mListener = NULL;
    mListenerSocket = NULL;
    mController = NULL;
    mDoArpProbe = false;
    pthread_mutex_init(&mLock, NULL);
}

DhcpClient::~DhcpClient() {
    delete mServiceManager;
    if (mListener)
        delete mListener;
}

int DhcpClient::start(Controller *c) {
    LOGD("Starting DHCP service (arp probe = %d)", mDoArpProbe);
    char svc[PROPERTY_VALUE_MAX];
    snprintf(svc,
             sizeof(svc),
             "dhcpcd:%s%s",
             (!mDoArpProbe ? "-A " : ""),
             c->getBoundInterface());

    pthread_mutex_lock(&mLock);

    if (mController) {
        pthread_mutex_unlock(&mLock);
        errno = EBUSY;
        return -1;
    }
    mController = c;

    sockaddr_in addr;
    if ((mListenerSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        LOGE("Failed to create DHCP listener socket");
        pthread_mutex_unlock(&mLock);
        return -1;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons(DhcpClient::STATUS_MONITOR_PORT);

    if (bind(mListenerSocket, (struct sockaddr *) &addr, sizeof(addr))) {
        LOGE("Failed to bind DHCP listener socket");
        close(mListenerSocket);
        mListenerSocket = -1;
        pthread_mutex_unlock(&mLock);
        return -1;
    }

    if (mServiceManager->start(svc)) {
        LOGE("Failed to start dhcp service");
        pthread_mutex_unlock(&mLock);
        return -1;
    }

    mListener = new DhcpListener(mController, mListenerSocket, mHandlers);
    if (mListener->startListener()) {
        LOGE("Failed to start listener");
#if 0
        mServiceManager->stop("dhcpcd");
        return -1;
#endif
        delete mListener;
        mListener = NULL;
        pthread_mutex_unlock(&mLock);
    }

    pthread_mutex_unlock(&mLock);
    return 0;
}

int DhcpClient::stop() {
    pthread_mutex_lock(&mLock);
    if (!mController) {
        pthread_mutex_unlock(&mLock);
        return 0;
    }

    if (mListener) {
        mListener->stopListener();
        delete mListener;
        mListener = NULL;
    }
    close(mListenerSocket);

    if (mServiceManager->stop("dhcpcd")) {
        LOGW("Failed to stop DHCP service (%s)", strerror(errno));
        // XXX: Kill it the hard way.. but its gotta go!
    }

    mController = NULL;
    pthread_mutex_unlock(&mLock);
    return 0;
}

void DhcpClient::setDoArpProbe(bool probe) {
    mDoArpProbe = probe;
}

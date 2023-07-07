/*
 * Copyright 2017, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cutils/qtaguid.h>

// #define LOG_NDEBUG 0

#define LOG_TAG "qtaguid"

#include <dlfcn.h>
#include <errno.h>
#include <inttypes.h>

#include <log/log.h>

struct netdHandler {
    int (*netdTagSocket)(int, uint32_t, uid_t);
    int (*netdUntagSocket)(int);
};

static int stubTagSocket(int, uint32_t, uid_t) {
    return -EREMOTEIO;
}

static int stubUntagSocket(int) {
    return -EREMOTEIO;
}

static netdHandler initHandler(void) {
    const netdHandler stubHandler = { stubTagSocket, stubUntagSocket };

    void* netdClientHandle = dlopen("libnetd_client.so", RTLD_NOW);
    if (!netdClientHandle) {
        ALOGE("Failed to open libnetd_client.so: %s", dlerror());
        return stubHandler;
    }

    netdHandler handler;
    handler.netdTagSocket = (int (*)(int, uint32_t, uid_t))dlsym(netdClientHandle, "tagSocket");
    if (!handler.netdTagSocket) {
        ALOGE("load netdTagSocket handler failed: %s", dlerror());
        return stubHandler;
    }

    handler.netdUntagSocket = (int (*)(int))dlsym(netdClientHandle, "untagSocket");
    if (!handler.netdUntagSocket) {
        ALOGE("load netdUntagSocket handler failed: %s", dlerror());
        return stubHandler;
    }

    return handler;
}

// The language guarantees that this object will be initialized in a thread-safe way.
static const netdHandler& getHandler() {
    static const netdHandler instance = initHandler();
    return instance;
}

int qtaguid_tagSocket(int sockfd, int tag, uid_t uid) {
    ALOGV("Tagging socket %d with tag %u for uid %d", sockfd, tag, uid);
    return getHandler().netdTagSocket(sockfd, tag, uid);
}

int qtaguid_untagSocket(int sockfd) {
    ALOGV("Untagging socket %d", sockfd);
    return getHandler().netdUntagSocket(sockfd);
}

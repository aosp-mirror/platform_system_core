/*
 * Copyright (C) 2012 The Android Open Source Project
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

#define LOG_TAG "libsuspend"
//#define LOG_NDEBUG 0

#include <fcntl.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/strings.h>

#include "autosuspend_ops.h"

#define BASE_SLEEP_TIME 100000
#define MAX_SLEEP_TIME 60000000

static int state_fd;
static int wakeup_count_fd;

using android::base::ReadFdToString;
using android::base::Trim;
using android::base::WriteStringToFd;

static pthread_t suspend_thread;
static sem_t suspend_lockout;
static const char* sleep_state = "mem";
static void (*wakeup_func)(bool success) = NULL;
static int sleep_time = BASE_SLEEP_TIME;
static constexpr char sys_power_state[] = "/sys/power/state";
static constexpr char sys_power_wakeup_count[] = "/sys/power/wakeup_count";

static void update_sleep_time(bool success) {
    if (success) {
        sleep_time = BASE_SLEEP_TIME;
        return;
    }
    // double sleep time after each failure up to one minute
    sleep_time = MIN(sleep_time * 2, MAX_SLEEP_TIME);
}

static void* suspend_thread_func(void* arg __attribute__((unused))) {
    int ret;
    bool success = true;

    while (1) {
        update_sleep_time(success);
        usleep(sleep_time);
        success = false;
        LOG(VERBOSE) << "read wakeup_count";
        lseek(wakeup_count_fd, 0, SEEK_SET);
        std::string wakeup_count;
        if (!ReadFdToString(wakeup_count_fd, &wakeup_count)) {
            PLOG(ERROR) << "error reading from " << sys_power_wakeup_count;
            continue;
        }

        wakeup_count = Trim(wakeup_count);
        if (wakeup_count.empty()) {
            LOG(ERROR) << "empty wakeup count";
            continue;
        }

        LOG(VERBOSE) << "wait";
        ret = sem_wait(&suspend_lockout);
        if (ret < 0) {
            PLOG(ERROR) << "error waiting on semaphore";
            continue;
        }

        LOG(VERBOSE) << "write " << wakeup_count << " to wakeup_count";
        if (WriteStringToFd(wakeup_count, wakeup_count_fd)) {
            LOG(VERBOSE) << "write " << sleep_state << " to " << sys_power_state;
            success = WriteStringToFd(sleep_state, state_fd);

            void (*func)(bool success) = wakeup_func;
            if (func != NULL) {
                (*func)(success);
            }
        } else {
            PLOG(ERROR) << "error writing to " << sys_power_wakeup_count;
        }

        LOG(VERBOSE) << "release sem";
        ret = sem_post(&suspend_lockout);
        if (ret < 0) {
            PLOG(ERROR) << "error releasing semaphore";
        }
    }
    return NULL;
}

static int autosuspend_wakeup_count_enable(void) {
    int ret;

    LOG(VERBOSE) << "autosuspend_wakeup_count_enable";

    ret = sem_post(&suspend_lockout);

    if (ret < 0) {
        PLOG(ERROR) << "error changing semaphore";
    }

    LOG(VERBOSE) << "autosuspend_wakeup_count_enable done";

    return ret;
}

static int autosuspend_wakeup_count_disable(void) {
    int ret;

    LOG(VERBOSE) << "autosuspend_wakeup_count_disable";

    ret = sem_wait(&suspend_lockout);

    if (ret < 0) {
        PLOG(ERROR) << "error changing semaphore";
    }

    LOG(VERBOSE) << "autosuspend_wakeup_count_disable done";

    return ret;
}

static void autosuspend_set_wakeup_callback(void (*func)(bool success)) {
    if (wakeup_func != NULL) {
        LOG(ERROR) << "duplicate wakeup callback applied, keeping original";
        return;
    }
    wakeup_func = func;
}

struct autosuspend_ops autosuspend_wakeup_count_ops = {
    .enable = autosuspend_wakeup_count_enable,
    .disable = autosuspend_wakeup_count_disable,
    .set_wakeup_callback = autosuspend_set_wakeup_callback,
};

struct autosuspend_ops* autosuspend_wakeup_count_init(void) {
    int ret;

    state_fd = TEMP_FAILURE_RETRY(open(sys_power_state, O_RDWR));
    if (state_fd < 0) {
        PLOG(ERROR) << "error opening " << sys_power_state;
        goto err_open_state;
    }

    wakeup_count_fd = TEMP_FAILURE_RETRY(open(sys_power_wakeup_count, O_RDWR));
    if (wakeup_count_fd < 0) {
        PLOG(ERROR) << "error opening " << sys_power_wakeup_count;
        goto err_open_wakeup_count;
    }

    ret = sem_init(&suspend_lockout, 0, 0);
    if (ret < 0) {
        PLOG(ERROR) << "error creating semaphore";
        goto err_sem_init;
    }
    ret = pthread_create(&suspend_thread, NULL, suspend_thread_func, NULL);
    if (ret) {
        LOG(ERROR) << "error creating thread: " << strerror(ret);
        goto err_pthread_create;
    }

    LOG(INFO) << "selected wakeup count";
    return &autosuspend_wakeup_count_ops;

err_pthread_create:
    sem_destroy(&suspend_lockout);
err_sem_init:
    close(wakeup_count_fd);
err_open_wakeup_count:
    close(state_fd);
err_open_state:
    return NULL;
}

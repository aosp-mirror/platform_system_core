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

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <semaphore.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define LOG_TAG "libsuspend"
//#define LOG_NDEBUG 0
#include <cutils/log.h>

#include "autosuspend_ops.h"

#define SYS_POWER_STATE "/sys/power/state"
#define SYS_POWER_WAKEUP_COUNT "/sys/power/wakeup_count"

static int state_fd;
static int wakeup_count_fd;
static pthread_t suspend_thread;
static sem_t suspend_lockout;
static const char *sleep_state = "mem";
static void (*wakeup_func)(bool success) = NULL;

static void *suspend_thread_func(void *arg __attribute__((unused)))
{
    char buf[80];
    char wakeup_count[20];
    int wakeup_count_len;
    int ret;
    bool success;

    while (1) {
        usleep(100000);
        ALOGV("%s: read wakeup_count\n", __func__);
        lseek(wakeup_count_fd, 0, SEEK_SET);
        wakeup_count_len = TEMP_FAILURE_RETRY(read(wakeup_count_fd, wakeup_count,
                sizeof(wakeup_count)));
        if (wakeup_count_len < 0) {
            strerror_r(errno, buf, sizeof(buf));
            ALOGE("Error reading from %s: %s\n", SYS_POWER_WAKEUP_COUNT, buf);
            wakeup_count_len = 0;
            continue;
        }
        if (!wakeup_count_len) {
            ALOGE("Empty wakeup count\n");
            continue;
        }

        ALOGV("%s: wait\n", __func__);
        ret = sem_wait(&suspend_lockout);
        if (ret < 0) {
            strerror_r(errno, buf, sizeof(buf));
            ALOGE("Error waiting on semaphore: %s\n", buf);
            continue;
        }

        success = true;
        ALOGV("%s: write %*s to wakeup_count\n", __func__, wakeup_count_len, wakeup_count);
        ret = TEMP_FAILURE_RETRY(write(wakeup_count_fd, wakeup_count, wakeup_count_len));
        if (ret < 0) {
            strerror_r(errno, buf, sizeof(buf));
            ALOGE("Error writing to %s: %s\n", SYS_POWER_WAKEUP_COUNT, buf);
        } else {
            ALOGV("%s: write %s to %s\n", __func__, sleep_state, SYS_POWER_STATE);
            ret = TEMP_FAILURE_RETRY(write(state_fd, sleep_state, strlen(sleep_state)));
            if (ret < 0) {
                success = false;
            }
            void (*func)(bool success) = wakeup_func;
            if (func != NULL) {
                (*func)(success);
            }
        }

        ALOGV("%s: release sem\n", __func__);
        ret = sem_post(&suspend_lockout);
        if (ret < 0) {
            strerror_r(errno, buf, sizeof(buf));
            ALOGE("Error releasing semaphore: %s\n", buf);
        }
    }
    return NULL;
}

static int autosuspend_wakeup_count_enable(void)
{
    char buf[80];
    int ret;

    ALOGV("autosuspend_wakeup_count_enable\n");

    ret = sem_post(&suspend_lockout);

    if (ret < 0) {
        strerror_r(errno, buf, sizeof(buf));
        ALOGE("Error changing semaphore: %s\n", buf);
    }

    ALOGV("autosuspend_wakeup_count_enable done\n");

    return ret;
}

static int autosuspend_wakeup_count_disable(void)
{
    char buf[80];
    int ret;

    ALOGV("autosuspend_wakeup_count_disable\n");

    ret = sem_wait(&suspend_lockout);

    if (ret < 0) {
        strerror_r(errno, buf, sizeof(buf));
        ALOGE("Error changing semaphore: %s\n", buf);
    }

    ALOGV("autosuspend_wakeup_count_disable done\n");

    return ret;
}

void set_wakeup_callback(void (*func)(bool success))
{
    if (wakeup_func != NULL) {
        ALOGE("Duplicate wakeup callback applied, keeping original");
        return;
    }
    wakeup_func = func;
}

struct autosuspend_ops autosuspend_wakeup_count_ops = {
        .enable = autosuspend_wakeup_count_enable,
        .disable = autosuspend_wakeup_count_disable,
};

struct autosuspend_ops *autosuspend_wakeup_count_init(void)
{
    int ret;
    char buf[80];

    state_fd = TEMP_FAILURE_RETRY(open(SYS_POWER_STATE, O_RDWR));
    if (state_fd < 0) {
        strerror_r(errno, buf, sizeof(buf));
        ALOGE("Error opening %s: %s\n", SYS_POWER_STATE, buf);
        goto err_open_state;
    }

    wakeup_count_fd = TEMP_FAILURE_RETRY(open(SYS_POWER_WAKEUP_COUNT, O_RDWR));
    if (wakeup_count_fd < 0) {
        strerror_r(errno, buf, sizeof(buf));
        ALOGE("Error opening %s: %s\n", SYS_POWER_WAKEUP_COUNT, buf);
        goto err_open_wakeup_count;
    }

    ret = sem_init(&suspend_lockout, 0, 0);
    if (ret < 0) {
        strerror_r(errno, buf, sizeof(buf));
        ALOGE("Error creating semaphore: %s\n", buf);
        goto err_sem_init;
    }
    ret = pthread_create(&suspend_thread, NULL, suspend_thread_func, NULL);
    if (ret) {
        strerror_r(ret, buf, sizeof(buf));
        ALOGE("Error creating thread: %s\n", buf);
        goto err_pthread_create;
    }

    ALOGI("Selected wakeup count\n");
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

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
#include <stddef.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#define LOG_TAG "libsuspend"
#include <cutils/log.h>

#include "autosuspend_ops.h"

#define EARLYSUSPEND_SYS_POWER_STATE "/sys/power/state"
#define EARLYSUSPEND_WAIT_FOR_FB_SLEEP "/sys/power/wait_for_fb_sleep"
#define EARLYSUSPEND_WAIT_FOR_FB_WAKE "/sys/power/wait_for_fb_wake"


static int sPowerStatefd;
static const char *pwr_state_mem = "mem";
static const char *pwr_state_on = "on";

static int autosuspend_earlysuspend_enable(void)
{
    char buf[80];
    int ret;

    ALOGV("autosuspend_earlysuspend_enable\n");

    ret = write(sPowerStatefd, pwr_state_mem, strlen(pwr_state_mem));
    if (ret < 0) {
        strerror_r(errno, buf, sizeof(buf));
        ALOGE("Error writing to %s: %s\n", EARLYSUSPEND_SYS_POWER_STATE, buf);
        goto err;
    }

    ALOGV("autosuspend_earlysuspend_enable done\n");

    return 0;

err:
    return ret;
}

static int autosuspend_earlysuspend_disable(void)
{
    char buf[80];
    int ret;

    ALOGV("autosuspend_earlysuspend_disable\n");

    ret = write(sPowerStatefd, pwr_state_on, strlen(pwr_state_on));
    if (ret < 0) {
        strerror_r(errno, buf, sizeof(buf));
        ALOGE("Error writing to %s: %s\n", EARLYSUSPEND_SYS_POWER_STATE, buf);
        goto err;
    }

    ALOGV("autosuspend_earlysuspend_disable done\n");

    return 0;

err:
    return ret;
}

struct autosuspend_ops autosuspend_earlysuspend_ops = {
        .enable = autosuspend_earlysuspend_enable,
        .disable = autosuspend_earlysuspend_disable,
};

struct autosuspend_ops *autosuspend_earlysuspend_init(void)
{
    char buf[80];
    int ret;

    ret = access(EARLYSUSPEND_WAIT_FOR_FB_SLEEP, F_OK);
    if (ret < 0) {
        return NULL;
    }

    ret = access(EARLYSUSPEND_WAIT_FOR_FB_WAKE, F_OK);
    if (ret < 0) {
        return NULL;
    }

    sPowerStatefd = open(EARLYSUSPEND_SYS_POWER_STATE, O_RDWR);

    if (sPowerStatefd < 0) {
        strerror_r(errno, buf, sizeof(buf));
        ALOGE("Error opening %s: %s\n", EARLYSUSPEND_SYS_POWER_STATE, buf);
        return NULL;
    }

    ALOGI("Selected early suspend\n");
    return &autosuspend_earlysuspend_ops;
}

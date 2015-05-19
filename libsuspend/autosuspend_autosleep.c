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
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define LOG_TAG "libsuspend"
#include <cutils/log.h>

#include "autosuspend_ops.h"

#define SYS_POWER_AUTOSLEEP "/sys/power/autosleep"

static int autosleep_fd;
static const char *sleep_state = "mem";
static const char *on_state = "off";

static int autosuspend_autosleep_enable(void)
{
    char buf[80];
    int ret;

    ALOGV("autosuspend_autosleep_enable\n");

    ret = TEMP_FAILURE_RETRY(write(autosleep_fd, sleep_state, strlen(sleep_state)));
    if (ret < 0) {
        strerror_r(errno, buf, sizeof(buf));
        ALOGE("Error writing to %s: %s\n", SYS_POWER_AUTOSLEEP, buf);
        goto err;
    }

    ALOGV("autosuspend_autosleep_enable done\n");

    return 0;

err:
    return ret;
}

static int autosuspend_autosleep_disable(void)
{
    char buf[80];
    int ret;

    ALOGV("autosuspend_autosleep_disable\n");

    ret = TEMP_FAILURE_RETRY(write(autosleep_fd, on_state, strlen(on_state)));
    if (ret < 0) {
        strerror_r(errno, buf, sizeof(buf));
        ALOGE("Error writing to %s: %s\n", SYS_POWER_AUTOSLEEP, buf);
        goto err;
    }

    ALOGV("autosuspend_autosleep_disable done\n");

    return 0;

err:
    return ret;
}

struct autosuspend_ops autosuspend_autosleep_ops = {
        .enable = autosuspend_autosleep_enable,
        .disable = autosuspend_autosleep_disable,
};

struct autosuspend_ops *autosuspend_autosleep_init(void)
{
    char buf[80];

    autosleep_fd = TEMP_FAILURE_RETRY(open(SYS_POWER_AUTOSLEEP, O_WRONLY));
    if (autosleep_fd < 0) {
        strerror_r(errno, buf, sizeof(buf));
        ALOGE("Error opening %s: %s\n", SYS_POWER_AUTOSLEEP, buf);
        return NULL;
    }

    ALOGI("Selected autosleep\n");

    autosuspend_autosleep_disable();

    return &autosuspend_autosleep_ops;
}

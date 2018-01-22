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

#include <stdbool.h>

#include <log/log.h>

#include <suspend/autosuspend.h>

#include "autosuspend_ops.h"

static struct autosuspend_ops* autosuspend_ops = NULL;
static bool autosuspend_enabled;

static int autosuspend_init(void) {
    if (autosuspend_ops != NULL) {
        return 0;
    }

    autosuspend_ops = autosuspend_wakeup_count_init();
    if (autosuspend_ops == NULL) {
        ALOGE("failed to initialize autosuspend");
        return -1;
    }

    ALOGV("autosuspend initialized");
    return 0;
}

int autosuspend_enable(void) {
    int ret;

    ret = autosuspend_init();
    if (ret) {
        return ret;
    }

    ALOGV("autosuspend_enable");

    if (autosuspend_enabled) {
        return 0;
    }

    ret = autosuspend_ops->enable();
    if (ret) {
        return ret;
    }

    autosuspend_enabled = true;
    return 0;
}

int autosuspend_disable(void) {
    int ret;

    ret = autosuspend_init();
    if (ret) {
        return ret;
    }

    ALOGV("autosuspend_disable");

    if (!autosuspend_enabled) {
        return 0;
    }

    ret = autosuspend_ops->disable();
    if (ret) {
        return ret;
    }

    autosuspend_enabled = false;
    return 0;
}

int autosuspend_force_suspend(int timeout_ms) {
    int ret;

    ret = autosuspend_init();
    if (ret) {
        return ret;
    }

    ALOGV("autosuspend_force_suspend");

    return autosuspend_ops->force_suspend(timeout_ms);
}

void autosuspend_set_wakeup_callback(void (*func)(bool success)) {
    int ret;

    ret = autosuspend_init();
    if (ret) {
        return;
    }

    ALOGV("set_wakeup_callback");

    autosuspend_ops->set_wakeup_callback(func);
}

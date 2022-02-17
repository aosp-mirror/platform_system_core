/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include <usbhost/usbhost_jni.h>

#include "usbhost_private.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>

jbyteArray usb_jni_read_descriptors(JNIEnv* env, int fd) {
    if (TEMP_FAILURE_RETRY(lseek(fd, 0, SEEK_SET)) == -1) {
        ALOGE("usb_jni_read_descriptors(%d): lseek() failed: %s", fd, strerror(errno));
        return NULL;
    }

    jbyte buf[MAX_DESCRIPTORS_LENGTH];
    ssize_t n = TEMP_FAILURE_RETRY(read(fd, buf, sizeof(buf)));
    if (n == -1) {
        ALOGE("usb_jni_read_descriptors: read failed: %s", strerror(errno));
        return NULL;
    }

    jbyteArray result = env->NewByteArray(n);
    if (result) env->SetByteArrayRegion(result, 0, n, buf);
    return result;
}

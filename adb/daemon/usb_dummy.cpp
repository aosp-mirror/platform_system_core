/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include <adbd/usb.h>

#include <android-base/logging.h>

int usb_write(usb_handle*, const void*, int) {
    LOG(FATAL) << "unimplemented";
    return -1;
}

int usb_read(usb_handle*, void*, int) {
    LOG(FATAL) << "unimplemented";
    return -1;
}

int usb_close(usb_handle*) {
    LOG(FATAL) << "unimplemented";
    return -1;
}

void usb_reset(usb_handle*) {
    LOG(FATAL) << "unimplemented";
}

void usb_kick(usb_handle*) {
    LOG(FATAL) << "unimplemented";
}

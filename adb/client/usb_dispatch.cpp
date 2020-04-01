/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include <android-base/logging.h>

#include "client/usb.h"

void usb_init() {
    if (should_use_libusb()) {
        LOG(DEBUG) << "using libusb backend";
        libusb::usb_init();
    } else {
        LOG(DEBUG) << "using native backend";
        native::usb_init();
    }
}

void usb_cleanup() {
    if (should_use_libusb()) {
        libusb::usb_cleanup();
    } else {
        native::usb_cleanup();
    }
}

int usb_write(usb_handle* h, const void* data, int len) {
    return should_use_libusb()
               ? libusb::usb_write(reinterpret_cast<libusb::usb_handle*>(h), data, len)
               : native::usb_write(reinterpret_cast<native::usb_handle*>(h), data, len);
}

int usb_read(usb_handle* h, void* data, int len) {
    return should_use_libusb()
               ? libusb::usb_read(reinterpret_cast<libusb::usb_handle*>(h), data, len)
               : native::usb_read(reinterpret_cast<native::usb_handle*>(h), data, len);
}

int usb_close(usb_handle* h) {
    return should_use_libusb() ? libusb::usb_close(reinterpret_cast<libusb::usb_handle*>(h))
                               : native::usb_close(reinterpret_cast<native::usb_handle*>(h));
}

void usb_reset(usb_handle* h) {
    should_use_libusb() ? libusb::usb_reset(reinterpret_cast<libusb::usb_handle*>(h))
                        : native::usb_reset(reinterpret_cast<native::usb_handle*>(h));
}

void usb_kick(usb_handle* h) {
    should_use_libusb() ? libusb::usb_kick(reinterpret_cast<libusb::usb_handle*>(h))
                        : native::usb_kick(reinterpret_cast<native::usb_handle*>(h));
}

size_t usb_get_max_packet_size(usb_handle* h) {
    return should_use_libusb()
               ? libusb::usb_get_max_packet_size(reinterpret_cast<libusb::usb_handle*>(h))
               : native::usb_get_max_packet_size(reinterpret_cast<native::usb_handle*>(h));
}

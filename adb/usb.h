/*
 * Copyright (C) 2016 The Android Open Source Project
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

#pragma once

#include <sys/types.h>

// USB host/client interface.

#define ADB_USB_INTERFACE(handle_ref_type)                       \
    void usb_init();                                             \
    void usb_cleanup();                                          \
    int usb_write(handle_ref_type h, const void* data, int len); \
    int usb_read(handle_ref_type h, void* data, int len);        \
    int usb_close(handle_ref_type h);                            \
    void usb_kick(handle_ref_type h);                            \
    size_t usb_get_max_packet_size(handle_ref_type)

#if !ADB_HOST
// The daemon has a single implementation.

struct usb_handle;
ADB_USB_INTERFACE(usb_handle*);

#else // linux host || darwin
// Linux and Darwin clients have native and libusb implementations.

namespace libusb {
    struct usb_handle;
    ADB_USB_INTERFACE(libusb::usb_handle*);
}

namespace native {
    struct usb_handle;
    ADB_USB_INTERFACE(native::usb_handle*);
}

// Empty base that both implementations' opaque handles inherit from.
struct usb_handle {
};

ADB_USB_INTERFACE(::usb_handle*);

#endif // linux host || darwin


// USB device detection.
int is_adb_interface(int usb_class, int usb_subclass, int usb_protocol);

bool should_use_libusb();

/*
 * Copyright (C) 2007 The Android Open Source Project
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

#define TRACE_TAG TRANSPORT

#include "sysdeps.h"
#include "transport.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "adb.h"

#if ADB_HOST

static constexpr size_t MAX_USB_BULK_PACKET_SIZE = 1024u;

// Call usb_read using a buffer having a multiple of MAX_USB_BULK_PACKET_SIZE bytes
// to avoid overflow. See http://libusb.sourceforge.net/api-1.0/packetoverflow.html.
static int UsbReadMessage(usb_handle* h, amessage* msg) {
    D("UsbReadMessage");
    char buffer[MAX_USB_BULK_PACKET_SIZE];
    int n = usb_read(h, buffer, sizeof(buffer));
    if (n == sizeof(*msg)) {
        memcpy(msg, buffer, sizeof(*msg));
    }
    return n;
}

// Call usb_read using a buffer having a multiple of MAX_USB_BULK_PACKET_SIZE bytes
// to avoid overflow. See http://libusb.sourceforge.net/api-1.0/packetoverflow.html.
static int UsbReadPayload(usb_handle* h, apacket* p) {
    D("UsbReadPayload");
    size_t need_size = p->msg.data_length;
    size_t data_pos = 0u;
    while (need_size > 0u) {
        int n = 0;
        if (data_pos + MAX_USB_BULK_PACKET_SIZE <= sizeof(p->data)) {
            // Read directly to p->data.
            size_t rem_size = need_size % MAX_USB_BULK_PACKET_SIZE;
            size_t direct_read_size = need_size - rem_size;
            if (rem_size &&
                data_pos + direct_read_size + MAX_USB_BULK_PACKET_SIZE <= sizeof(p->data)) {
                direct_read_size += MAX_USB_BULK_PACKET_SIZE;
            }
            n = usb_read(h, &p->data[data_pos], direct_read_size);
            if (n < 0) {
                D("usb_read(size %zu) failed", direct_read_size);
                return n;
            }
        } else {
            // Read indirectly using a buffer.
            char buffer[MAX_USB_BULK_PACKET_SIZE];
            n = usb_read(h, buffer, sizeof(buffer));
            if (n < 0) {
                D("usb_read(size %zu) failed", sizeof(buffer));
                return -1;
            }
            size_t copy_size = std::min(static_cast<size_t>(n), need_size);
            D("usb read %d bytes, need %zu bytes, copy %zu bytes", n, need_size, copy_size);
            memcpy(&p->data[data_pos], buffer, copy_size);
        }
        data_pos += n;
        need_size -= std::min(static_cast<size_t>(n), need_size);
    }
    return static_cast<int>(data_pos);
}

static int remote_read(apacket* p, atransport* t) {
    int n = UsbReadMessage(t->usb, &p->msg);
    if (n < 0) {
        D("remote usb: read terminated (message)");
        return -1;
    }
    if (static_cast<size_t>(n) != sizeof(p->msg) || check_header(p, t)) {
        D("remote usb: check_header failed, skip it");
        goto err_msg;
    }
    if (t->GetConnectionState() == kCsOffline) {
        // If we read a wrong msg header declaring a large message payload, don't read its payload.
        // Otherwise we may miss true messages from the device.
        if (p->msg.command != A_CNXN && p->msg.command != A_AUTH) {
            goto err_msg;
        }
    }
    if (p->msg.data_length) {
        n = UsbReadPayload(t->usb, p);
        if (n < 0) {
            D("remote usb: terminated (data)");
            return -1;
        }
        if (static_cast<uint32_t>(n) != p->msg.data_length) {
            D("remote usb: read payload failed (need %u bytes, give %d bytes), skip it",
              p->msg.data_length, n);
            goto err_msg;
        }
    }
    if (check_data(p)) {
        D("remote usb: check_data failed, skip it");
        goto err_msg;
    }
    return 0;

err_msg:
    p->msg.command = 0;
    if (t->GetConnectionState() == kCsOffline) {
        // If the data toggle of ep_out on device and ep_in on host are not the same, we may receive
        // an error message. In this case, resend one A_CNXN message to connect the device.
        if (t->SetSendConnectOnError()) {
            SendConnectOnHost(t);
        }
    }
    return 0;
}

#else

// On Android devices, we rely on the kernel to provide buffered read.
// So we can recover automatically from EOVERFLOW.
static int remote_read(apacket *p, atransport *t)
{
    if (usb_read(t->usb, &p->msg, sizeof(amessage))) {
        D("remote usb: read terminated (message)");
        return -1;
    }

    if(check_header(p, t)) {
        D("remote usb: check_header failed");
        return -1;
    }

    if(p->msg.data_length) {
        if (usb_read(t->usb, p->data, p->msg.data_length)) {
            D("remote usb: terminated (data)");
            return -1;
        }
    }

    if(check_data(p)) {
        D("remote usb: check_data failed");
        return -1;
    }

    return 0;
}
#endif

static int remote_write(apacket *p, atransport *t)
{
    unsigned size = p->msg.data_length;

    if (usb_write(t->usb, &p->msg, sizeof(amessage))) {
        D("remote usb: 1 - write terminated");
        return -1;
    }
    if(p->msg.data_length == 0) return 0;
    if (usb_write(t->usb, &p->data, size)) {
        D("remote usb: 2 - write terminated");
        return -1;
    }

    return 0;
}

static void remote_close(atransport *t)
{
    usb_close(t->usb);
    t->usb = 0;
}

static void remote_kick(atransport* t) {
    usb_kick(t->usb);
}

void init_usb_transport(atransport* t, usb_handle* h) {
    D("transport: usb");
    t->close = remote_close;
    t->SetKickFunction(remote_kick);
    t->SetWriteFunction(remote_write);
    t->read_from_remote = remote_read;
    t->sync_token = 1;
    t->type = kTransportUsb;
    t->usb = h;
}

int is_adb_interface(int usb_class, int usb_subclass, int usb_protocol)
{
    return (usb_class == ADB_CLASS && usb_subclass == ADB_SUBCLASS && usb_protocol == ADB_PROTOCOL);
}

bool should_use_libusb() {
#if defined(_WIN32) || !ADB_HOST
    return false;
#else
    static bool disable = getenv("ADB_LIBUSB") && strcmp(getenv("ADB_LIBUSB"), "0") == 0;
    return !disable;
#endif
}

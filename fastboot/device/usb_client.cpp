/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include "usb_client.h"

#include <endian.h>
#include <fcntl.h>
#include <linux/usb/ch9.h>
#include <linux/usb/functionfs.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <android-base/logging.h>
#include <android-base/properties.h>

constexpr int kMaxPacketSizeFs = 64;
constexpr int kMaxPacketSizeHs = 512;
constexpr int kMaxPacketsizeSs = 1024;

constexpr size_t kFbFfsNumBufs = 16;
constexpr size_t kFbFfsBufSize = 16384;

constexpr const char* kUsbFfsFastbootEp0 = "/dev/usb-ffs/fastboot/ep0";
constexpr const char* kUsbFfsFastbootOut = "/dev/usb-ffs/fastboot/ep1";
constexpr const char* kUsbFfsFastbootIn = "/dev/usb-ffs/fastboot/ep2";

struct FuncDesc {
    struct usb_interface_descriptor intf;
    struct usb_endpoint_descriptor_no_audio source;
    struct usb_endpoint_descriptor_no_audio sink;
} __attribute__((packed));

struct SsFuncDesc {
    struct usb_interface_descriptor intf;
    struct usb_endpoint_descriptor_no_audio source;
    struct usb_ss_ep_comp_descriptor source_comp;
    struct usb_endpoint_descriptor_no_audio sink;
    struct usb_ss_ep_comp_descriptor sink_comp;
} __attribute__((packed));

struct DescV2 {
    struct usb_functionfs_descs_head_v2 header;
    // The rest of the structure depends on the flags in the header.
    __le32 fs_count;
    __le32 hs_count;
    __le32 ss_count;
    struct FuncDesc fs_descs, hs_descs;
    struct SsFuncDesc ss_descs;
} __attribute__((packed));

struct usb_interface_descriptor fastboot_interface = {
        .bLength = USB_DT_INTERFACE_SIZE,
        .bDescriptorType = USB_DT_INTERFACE,
        .bInterfaceNumber = 0,
        .bNumEndpoints = 2,
        .bInterfaceClass = USB_CLASS_VENDOR_SPEC,
        .bInterfaceSubClass = 66,
        .bInterfaceProtocol = 3,
        .iInterface = 1, /* first string from the provided table */
};

static struct FuncDesc fs_descriptors = {
        .intf = fastboot_interface,
        .source =
                {
                        .bLength = sizeof(fs_descriptors.source),
                        .bDescriptorType = USB_DT_ENDPOINT,
                        .bEndpointAddress = 1 | USB_DIR_OUT,
                        .bmAttributes = USB_ENDPOINT_XFER_BULK,
                        .wMaxPacketSize = kMaxPacketSizeFs,
                },
        .sink =
                {
                        .bLength = sizeof(fs_descriptors.sink),
                        .bDescriptorType = USB_DT_ENDPOINT,
                        .bEndpointAddress = 1 | USB_DIR_IN,
                        .bmAttributes = USB_ENDPOINT_XFER_BULK,
                        .wMaxPacketSize = kMaxPacketSizeFs,
                },
};

static struct FuncDesc hs_descriptors = {
        .intf = fastboot_interface,
        .source =
                {
                        .bLength = sizeof(hs_descriptors.source),
                        .bDescriptorType = USB_DT_ENDPOINT,
                        .bEndpointAddress = 1 | USB_DIR_OUT,
                        .bmAttributes = USB_ENDPOINT_XFER_BULK,
                        .wMaxPacketSize = kMaxPacketSizeHs,
                },
        .sink =
                {
                        .bLength = sizeof(hs_descriptors.sink),
                        .bDescriptorType = USB_DT_ENDPOINT,
                        .bEndpointAddress = 1 | USB_DIR_IN,
                        .bmAttributes = USB_ENDPOINT_XFER_BULK,
                        .wMaxPacketSize = kMaxPacketSizeHs,
                },
};

static struct SsFuncDesc ss_descriptors = {
        .intf = fastboot_interface,
        .source =
                {
                        .bLength = sizeof(ss_descriptors.source),
                        .bDescriptorType = USB_DT_ENDPOINT,
                        .bEndpointAddress = 1 | USB_DIR_OUT,
                        .bmAttributes = USB_ENDPOINT_XFER_BULK,
                        .wMaxPacketSize = kMaxPacketsizeSs,
                },
        .source_comp =
                {
                        .bLength = sizeof(ss_descriptors.source_comp),
                        .bDescriptorType = USB_DT_SS_ENDPOINT_COMP,
                        .bMaxBurst = 15,
                },
        .sink =
                {
                        .bLength = sizeof(ss_descriptors.sink),
                        .bDescriptorType = USB_DT_ENDPOINT,
                        .bEndpointAddress = 1 | USB_DIR_IN,
                        .bmAttributes = USB_ENDPOINT_XFER_BULK,
                        .wMaxPacketSize = kMaxPacketsizeSs,
                },
        .sink_comp =
                {
                        .bLength = sizeof(ss_descriptors.sink_comp),
                        .bDescriptorType = USB_DT_SS_ENDPOINT_COMP,
                        .bMaxBurst = 15,
                },
};

#define STR_INTERFACE_ "fastboot"

static const struct {
    struct usb_functionfs_strings_head header;
    struct {
        __le16 code;
        const char str1[sizeof(STR_INTERFACE_)];
    } __attribute__((packed)) lang0;
} __attribute__((packed)) strings = {
        .header =
                {
                        .magic = htole32(FUNCTIONFS_STRINGS_MAGIC),
                        .length = htole32(sizeof(strings)),
                        .str_count = htole32(1),
                        .lang_count = htole32(1),
                },
        .lang0 =
                {
                        htole16(0x0409), /* en-us */
                        STR_INTERFACE_,
                },
};

static struct DescV2 v2_descriptor = {
        .header =
                {
                        .magic = htole32(FUNCTIONFS_DESCRIPTORS_MAGIC_V2),
                        .length = htole32(sizeof(v2_descriptor)),
                        .flags = FUNCTIONFS_HAS_FS_DESC | FUNCTIONFS_HAS_HS_DESC |
                                 FUNCTIONFS_HAS_SS_DESC,
                },
        .fs_count = 3,
        .hs_count = 3,
        .ss_count = 5,
        .fs_descs = fs_descriptors,
        .hs_descs = hs_descriptors,
        .ss_descs = ss_descriptors,
};

// Reimplementing since usb_ffs_close() does not close the control FD.
static void CloseFunctionFs(usb_handle* h) {
    h->bulk_in.reset();
    h->bulk_out.reset();
    h->control.reset();
}

static bool InitFunctionFs(usb_handle* h) {
    LOG(INFO) << "initializing functionfs";

    if (h->control < 0) {  // might have already done this before
        LOG(INFO) << "opening control endpoint " << kUsbFfsFastbootEp0;
        h->control.reset(open(kUsbFfsFastbootEp0, O_RDWR));
        if (h->control < 0) {
            PLOG(ERROR) << "cannot open control endpoint " << kUsbFfsFastbootEp0;
            goto err;
        }

        auto ret = write(h->control.get(), &v2_descriptor, sizeof(v2_descriptor));
        if (ret < 0) {
            PLOG(ERROR) << "cannot write descriptors " << kUsbFfsFastbootEp0;
            goto err;
        }

        ret = write(h->control.get(), &strings, sizeof(strings));
        if (ret < 0) {
            PLOG(ERROR) << "cannot write strings " << kUsbFfsFastbootEp0;
            goto err;
        }
        // Signal only when writing the descriptors to ffs
        android::base::SetProperty("sys.usb.ffs.ready", "1");
    }

    h->bulk_out.reset(open(kUsbFfsFastbootOut, O_RDONLY));
    if (h->bulk_out < 0) {
        PLOG(ERROR) << "cannot open bulk-out endpoint " << kUsbFfsFastbootOut;
        goto err;
    }

    h->bulk_in.reset(open(kUsbFfsFastbootIn, O_WRONLY));
    if (h->bulk_in < 0) {
        PLOG(ERROR) << "cannot open bulk-in endpoint " << kUsbFfsFastbootIn;
        goto err;
    }

    h->read_aiob.fd = h->bulk_out.get();
    h->write_aiob.fd = h->bulk_in.get();
    h->reads_zero_packets = false;
    return true;

err:
    CloseFunctionFs(h);
    return false;
}

ClientUsbTransport::ClientUsbTransport()
    : handle_(std::unique_ptr<usb_handle>(create_usb_handle(kFbFfsNumBufs, kFbFfsBufSize))) {
    if (!InitFunctionFs(handle_.get())) {
        handle_.reset(nullptr);
    }
}

ssize_t ClientUsbTransport::Read(void* data, size_t len) {
    if (handle_ == nullptr || len > SSIZE_MAX) {
        return -1;
    }
    char* char_data = static_cast<char*>(data);
    size_t bytes_read_total = 0;
    while (bytes_read_total < len) {
        auto bytes_to_read = std::min(len - bytes_read_total, kFbFfsNumBufs * kFbFfsBufSize);
        auto bytes_read_now =
                handle_->read(handle_.get(), char_data, bytes_to_read, true /* allow_partial */);
        if (bytes_read_now < 0) {
            return bytes_read_total;
        }
        bytes_read_total += bytes_read_now;
        char_data += bytes_read_now;
        if (static_cast<size_t>(bytes_read_now) < bytes_to_read) {
            break;
        }
    }
    return bytes_read_total;
}

ssize_t ClientUsbTransport::Write(const void* data, size_t len) {
    if (handle_ == nullptr || len > SSIZE_MAX) {
        return -1;
    }
    const char* char_data = reinterpret_cast<const char*>(data);
    size_t bytes_written_total = 0;
    while (bytes_written_total < len) {
        auto bytes_to_write = std::min(len - bytes_written_total, kFbFfsNumBufs * kFbFfsBufSize);
        auto bytes_written_now = handle_->write(handle_.get(), data, bytes_to_write);
        if (bytes_written_now < 0) {
            return bytes_written_total;
        }
        bytes_written_total += bytes_written_now;
        char_data += bytes_written_now;
        if (static_cast<size_t>(bytes_written_now) < bytes_to_write) {
            break;
        }
    }
    return bytes_written_total;
}

int ClientUsbTransport::Close() {
    if (handle_ == nullptr) {
        return -1;
    }
    CloseFunctionFs(handle_.get());
    return 0;
}

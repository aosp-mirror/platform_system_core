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

#define TRACE_TAG USB

#include "sysdeps.h"

#include <linux/usb/ch9.h>
#include <linux/usb/functionfs.h>

#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/unique_fd.h>

#include "adb.h"
#include "adbd/usb.h"

#define MAX_PACKET_SIZE_FS 64
#define MAX_PACKET_SIZE_HS 512
#define MAX_PACKET_SIZE_SS 1024

#define USB_FFS_BULK_SIZE 16384

// Number of buffers needed to fit MAX_PAYLOAD, with an extra for ZLPs.
#define USB_FFS_NUM_BUFS ((4 * MAX_PAYLOAD / USB_FFS_BULK_SIZE) + 1)

#define cpu_to_le16(x) htole16(x)
#define cpu_to_le32(x) htole32(x)

struct func_desc {
    struct usb_interface_descriptor intf;
    struct usb_endpoint_descriptor_no_audio source;
    struct usb_endpoint_descriptor_no_audio sink;
} __attribute__((packed));

struct ss_func_desc {
    struct usb_interface_descriptor intf;
    struct usb_endpoint_descriptor_no_audio source;
    struct usb_ss_ep_comp_descriptor source_comp;
    struct usb_endpoint_descriptor_no_audio sink;
    struct usb_ss_ep_comp_descriptor sink_comp;
} __attribute__((packed));

struct desc_v1 {
    struct usb_functionfs_descs_head_v1 {
        __le32 magic;
        __le32 length;
        __le32 fs_count;
        __le32 hs_count;
    } __attribute__((packed)) header;
    struct func_desc fs_descs, hs_descs;
} __attribute__((packed));

struct desc_v2 {
    struct usb_functionfs_descs_head_v2 header;
    // The rest of the structure depends on the flags in the header.
    __le32 fs_count;
    __le32 hs_count;
    __le32 ss_count;
    __le32 os_count;
    struct func_desc fs_descs, hs_descs;
    struct ss_func_desc ss_descs;
    struct usb_os_desc_header os_header;
    struct usb_ext_compat_desc os_desc;
} __attribute__((packed));

// clang-format off
static struct func_desc fs_descriptors = {
    .intf = {
        .bLength = sizeof(fs_descriptors.intf),
        .bDescriptorType = USB_DT_INTERFACE,
        .bInterfaceNumber = 0,
        .bNumEndpoints = 2,
        .bInterfaceClass = ADB_CLASS,
        .bInterfaceSubClass = ADB_SUBCLASS,
        .bInterfaceProtocol = ADB_PROTOCOL,
        .iInterface = 1, /* first string from the provided table */
    },
    .source = {
        .bLength = sizeof(fs_descriptors.source),
        .bDescriptorType = USB_DT_ENDPOINT,
        .bEndpointAddress = 1 | USB_DIR_OUT,
        .bmAttributes = USB_ENDPOINT_XFER_BULK,
        .wMaxPacketSize = MAX_PACKET_SIZE_FS,
    },
    .sink = {
        .bLength = sizeof(fs_descriptors.sink),
        .bDescriptorType = USB_DT_ENDPOINT,
        .bEndpointAddress = 2 | USB_DIR_IN,
        .bmAttributes = USB_ENDPOINT_XFER_BULK,
        .wMaxPacketSize = MAX_PACKET_SIZE_FS,
    },
};

static struct func_desc hs_descriptors = {
    .intf = {
        .bLength = sizeof(hs_descriptors.intf),
        .bDescriptorType = USB_DT_INTERFACE,
        .bInterfaceNumber = 0,
        .bNumEndpoints = 2,
        .bInterfaceClass = ADB_CLASS,
        .bInterfaceSubClass = ADB_SUBCLASS,
        .bInterfaceProtocol = ADB_PROTOCOL,
        .iInterface = 1, /* first string from the provided table */
    },
    .source = {
        .bLength = sizeof(hs_descriptors.source),
        .bDescriptorType = USB_DT_ENDPOINT,
        .bEndpointAddress = 1 | USB_DIR_OUT,
        .bmAttributes = USB_ENDPOINT_XFER_BULK,
        .wMaxPacketSize = MAX_PACKET_SIZE_HS,
    },
    .sink = {
        .bLength = sizeof(hs_descriptors.sink),
        .bDescriptorType = USB_DT_ENDPOINT,
        .bEndpointAddress = 2 | USB_DIR_IN,
        .bmAttributes = USB_ENDPOINT_XFER_BULK,
        .wMaxPacketSize = MAX_PACKET_SIZE_HS,
    },
};

static struct ss_func_desc ss_descriptors = {
    .intf = {
        .bLength = sizeof(ss_descriptors.intf),
        .bDescriptorType = USB_DT_INTERFACE,
        .bInterfaceNumber = 0,
        .bNumEndpoints = 2,
        .bInterfaceClass = ADB_CLASS,
        .bInterfaceSubClass = ADB_SUBCLASS,
        .bInterfaceProtocol = ADB_PROTOCOL,
        .iInterface = 1, /* first string from the provided table */
    },
    .source = {
        .bLength = sizeof(ss_descriptors.source),
        .bDescriptorType = USB_DT_ENDPOINT,
        .bEndpointAddress = 1 | USB_DIR_OUT,
        .bmAttributes = USB_ENDPOINT_XFER_BULK,
        .wMaxPacketSize = MAX_PACKET_SIZE_SS,
    },
    .source_comp = {
        .bLength = sizeof(ss_descriptors.source_comp),
        .bDescriptorType = USB_DT_SS_ENDPOINT_COMP,
        .bMaxBurst = 4,
    },
    .sink = {
        .bLength = sizeof(ss_descriptors.sink),
        .bDescriptorType = USB_DT_ENDPOINT,
        .bEndpointAddress = 2 | USB_DIR_IN,
        .bmAttributes = USB_ENDPOINT_XFER_BULK,
        .wMaxPacketSize = MAX_PACKET_SIZE_SS,
    },
    .sink_comp = {
        .bLength = sizeof(ss_descriptors.sink_comp),
        .bDescriptorType = USB_DT_SS_ENDPOINT_COMP,
        .bMaxBurst = 4,
    },
};

struct usb_ext_compat_desc os_desc_compat = {
    .bFirstInterfaceNumber = 0,
    .Reserved1 = cpu_to_le32(1),
    .CompatibleID = {0},
    .SubCompatibleID = {0},
    .Reserved2 = {0},
};

static struct usb_os_desc_header os_desc_header = {
    .interface = cpu_to_le32(1),
    .dwLength = cpu_to_le32(sizeof(os_desc_header) + sizeof(os_desc_compat)),
    .bcdVersion = cpu_to_le32(1),
    .wIndex = cpu_to_le32(4),
    .bCount = cpu_to_le32(1),
    .Reserved = cpu_to_le32(0),
};

#define STR_INTERFACE_ "ADB Interface"

static const struct {
    struct usb_functionfs_strings_head header;
    struct {
        __le16 code;
        const char str1[sizeof(STR_INTERFACE_)];
    } __attribute__((packed)) lang0;
} __attribute__((packed)) strings = {
    .header = {
        .magic = cpu_to_le32(FUNCTIONFS_STRINGS_MAGIC),
        .length = cpu_to_le32(sizeof(strings)),
        .str_count = cpu_to_le32(1),
        .lang_count = cpu_to_le32(1),
    },
    .lang0 = {
        cpu_to_le16(0x0409), /* en-us */
        STR_INTERFACE_,
    },
};
// clang-format on

bool open_functionfs(android::base::unique_fd* out_control, android::base::unique_fd* out_bulk_out,
                     android::base::unique_fd* out_bulk_in) {
    unique_fd control, bulk_out, bulk_in;
    struct desc_v1 v1_descriptor = {};
    struct desc_v2 v2_descriptor = {};

    v2_descriptor.header.magic = cpu_to_le32(FUNCTIONFS_DESCRIPTORS_MAGIC_V2);
    v2_descriptor.header.length = cpu_to_le32(sizeof(v2_descriptor));
    v2_descriptor.header.flags = FUNCTIONFS_HAS_FS_DESC | FUNCTIONFS_HAS_HS_DESC |
                                 FUNCTIONFS_HAS_SS_DESC | FUNCTIONFS_HAS_MS_OS_DESC;
    v2_descriptor.fs_count = 3;
    v2_descriptor.hs_count = 3;
    v2_descriptor.ss_count = 5;
    v2_descriptor.os_count = 1;
    v2_descriptor.fs_descs = fs_descriptors;
    v2_descriptor.hs_descs = hs_descriptors;
    v2_descriptor.ss_descs = ss_descriptors;
    v2_descriptor.os_header = os_desc_header;
    v2_descriptor.os_desc = os_desc_compat;

    if (out_control->get() < 0) {  // might have already done this before
        LOG(INFO) << "opening control endpoint " << USB_FFS_ADB_EP0;
        control.reset(adb_open(USB_FFS_ADB_EP0, O_RDWR));
        if (control < 0) {
            PLOG(ERROR) << "cannot open control endpoint " << USB_FFS_ADB_EP0;
            return false;
        }

        if (adb_write(control.get(), &v2_descriptor, sizeof(v2_descriptor)) < 0) {
            D("[ %s: Switching to V1_descriptor format errno=%s ]", USB_FFS_ADB_EP0,
              strerror(errno));
            v1_descriptor.header.magic = cpu_to_le32(FUNCTIONFS_DESCRIPTORS_MAGIC);
            v1_descriptor.header.length = cpu_to_le32(sizeof(v1_descriptor));
            v1_descriptor.header.fs_count = 3;
            v1_descriptor.header.hs_count = 3;
            v1_descriptor.fs_descs = fs_descriptors;
            v1_descriptor.hs_descs = hs_descriptors;
            if (adb_write(control.get(), &v1_descriptor, sizeof(v1_descriptor)) < 0) {
                PLOG(ERROR) << "failed to write USB descriptors";
                return false;
            }
        }

        if (adb_write(control.get(), &strings, sizeof(strings)) < 0) {
            PLOG(ERROR) << "failed to write USB strings";
            return false;
        }
        // Signal only when writing the descriptors to ffs
        android::base::SetProperty("sys.usb.ffs.ready", "1");
    }

    bulk_out.reset(adb_open(USB_FFS_ADB_OUT, O_RDONLY));
    if (bulk_out < 0) {
        PLOG(ERROR) << "cannot open bulk-out endpoint " << USB_FFS_ADB_OUT;
        return false;
    }

    bulk_in.reset(adb_open(USB_FFS_ADB_IN, O_WRONLY));
    if (bulk_in < 0) {
        PLOG(ERROR) << "cannot open bulk-in endpoint " << USB_FFS_ADB_IN;
        return false;
    }

    *out_control = std::move(control);
    *out_bulk_in = std::move(bulk_in);
    *out_bulk_out = std::move(bulk_out);
    return true;
}

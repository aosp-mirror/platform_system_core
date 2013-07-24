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

#include <endian.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/types.h>

#include <linux/usb/ch9.h>
#include <linux/usb/functionfs.h>

#include "debug.h"
#include "transport.h"

#define   TRACE_TAG  TRACE_USB

#define MAX_PACKET_SIZE_FS     64
#define MAX_PACKET_SIZE_HS     512

#define cpu_to_le16(x)  htole16(x)
#define cpu_to_le32(x)  htole32(x)

#define FASTBOOT_CLASS         0xff
#define FASTBOOT_SUBCLASS      0x42
#define FASTBOOT_PROTOCOL      0x3

#define USB_FFS_FASTBOOT_PATH  "/dev/usb-ffs/adb/"
#define USB_FFS_FASTBOOT_EP(x) USB_FFS_FASTBOOT_PATH#x

#define USB_FFS_FASTBOOT_EP0   USB_FFS_FASTBOOT_EP(ep0)
#define USB_FFS_FASTBOOT_OUT   USB_FFS_FASTBOOT_EP(ep1)
#define USB_FFS_FASTBOOT_IN    USB_FFS_FASTBOOT_EP(ep2)

#define READ_BUF_SIZE (16*1024)

#define container_of(ptr, type, member) \
    ((type*)((char*)(ptr) - offsetof(type, member)))

struct usb_transport {
    struct transport transport;

    pthread_cond_t notify;
    pthread_mutex_t lock;

    int control;
    int bulk_out; /* "out" from the host's perspective => source for fastbootd */
    int bulk_in;  /* "in" from the host's perspective => sink for fastbootd */
};

struct usb_handle {
    struct transport_handle handle;
};

static const struct {
    struct usb_functionfs_descs_head header;
    struct {
        struct usb_interface_descriptor intf;
        struct usb_endpoint_descriptor_no_audio source;
        struct usb_endpoint_descriptor_no_audio sink;
    } __attribute__((packed)) fs_descs, hs_descs;
} __attribute__((packed)) descriptors = {
    .header = {
        .magic = cpu_to_le32(FUNCTIONFS_DESCRIPTORS_MAGIC),
        .length = cpu_to_le32(sizeof(descriptors)),
        .fs_count = 3,
        .hs_count = 3,
    },
    .fs_descs = {
        .intf = {
            .bLength = sizeof(descriptors.fs_descs.intf),
            .bDescriptorType = USB_DT_INTERFACE,
            .bInterfaceNumber = 0,
            .bNumEndpoints = 2,
            .bInterfaceClass = FASTBOOT_CLASS,
            .bInterfaceSubClass = FASTBOOT_SUBCLASS,
            .bInterfaceProtocol = FASTBOOT_PROTOCOL,
            .iInterface = 1, /* first string from the provided table */
        },
        .source = {
            .bLength = sizeof(descriptors.fs_descs.source),
            .bDescriptorType = USB_DT_ENDPOINT,
            .bEndpointAddress = 1 | USB_DIR_OUT,
            .bmAttributes = USB_ENDPOINT_XFER_BULK,
            .wMaxPacketSize = MAX_PACKET_SIZE_FS,
        },
        .sink = {
            .bLength = sizeof(descriptors.fs_descs.sink),
            .bDescriptorType = USB_DT_ENDPOINT,
            .bEndpointAddress = 2 | USB_DIR_IN,
            .bmAttributes = USB_ENDPOINT_XFER_BULK,
            .wMaxPacketSize = MAX_PACKET_SIZE_FS,
        },
    },
    .hs_descs = {
        .intf = {
            .bLength = sizeof(descriptors.hs_descs.intf),
            .bDescriptorType = USB_DT_INTERFACE,
            .bInterfaceNumber = 0,
            .bNumEndpoints = 2,
            .bInterfaceClass = FASTBOOT_CLASS,
            .bInterfaceSubClass = FASTBOOT_SUBCLASS,
            .bInterfaceProtocol = FASTBOOT_PROTOCOL,
            .iInterface = 1, /* first string from the provided table */
        },
        .source = {
            .bLength = sizeof(descriptors.hs_descs.source),
            .bDescriptorType = USB_DT_ENDPOINT,
            .bEndpointAddress = 1 | USB_DIR_OUT,
            .bmAttributes = USB_ENDPOINT_XFER_BULK,
            .wMaxPacketSize = MAX_PACKET_SIZE_HS,
        },
        .sink = {
            .bLength = sizeof(descriptors.hs_descs.sink),
            .bDescriptorType = USB_DT_ENDPOINT,
            .bEndpointAddress = 2 | USB_DIR_IN,
            .bmAttributes = USB_ENDPOINT_XFER_BULK,
            .wMaxPacketSize = MAX_PACKET_SIZE_HS,
        },
    },
};

#define STR_INTERFACE_ "Fastboot Interface"

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

static int init_functionfs(struct usb_transport *usb_transport)
{
    ssize_t ret;

    D(VERBOSE, "OPENING %s", USB_FFS_FASTBOOT_EP0);
    usb_transport->control = open(USB_FFS_FASTBOOT_EP0, O_RDWR);
    if (usb_transport->control < 0) {
        D(ERR, "[ %s: cannot open control endpoint: errno=%d]", USB_FFS_FASTBOOT_EP0, errno);
        goto err;
    }

    ret = write(usb_transport->control, &descriptors, sizeof(descriptors));
    if (ret < 0) {
        D(ERR, "[ %s: write descriptors failed: errno=%d ]", USB_FFS_FASTBOOT_EP0, errno);
        goto err;
    }

    ret = write(usb_transport->control, &strings, sizeof(strings));
    if (ret < 0) {
        D(ERR, "[ %s: writing strings failed: errno=%d]", USB_FFS_FASTBOOT_EP0, errno);
        goto err;
    }

    usb_transport->bulk_out = open(USB_FFS_FASTBOOT_OUT, O_RDWR);
    if (usb_transport->bulk_out < 0) {
        D(ERR, "[ %s: cannot open bulk-out ep: errno=%d ]", USB_FFS_FASTBOOT_OUT, errno);
        goto err;
    }

    usb_transport->bulk_in = open(USB_FFS_FASTBOOT_IN, O_RDWR);
    if (usb_transport->bulk_in < 0) {
        D(ERR, "[ %s: cannot open bulk-in ep: errno=%d ]", USB_FFS_FASTBOOT_IN, errno);
        goto err;
    }

    return 0;

err:
    if (usb_transport->bulk_in > 0) {
        close(usb_transport->bulk_in);
        usb_transport->bulk_in = -1;
    }
    if (usb_transport->bulk_out > 0) {
        close(usb_transport->bulk_out);
        usb_transport->bulk_out = -1;
    }
    if (usb_transport->control > 0) {
        close(usb_transport->control);
        usb_transport->control = -1;
    }
    return -1;
}

static ssize_t bulk_write(int bulk_in, const char *buf, size_t length)
{
    size_t count = 0;
    ssize_t ret;

    do {
        ret = TEMP_FAILURE_RETRY(write(bulk_in, buf + count, length - count));
        if (ret < 0) {
            D(WARN, "[ bulk_read failed fd=%d length=%d errno=%d %s ]",
                    bulk_in, length, errno, strerror(errno));
            return -1;
        } else {
            count += ret;
        }
    } while (count < length);

    D(VERBOSE, "[ bulk_write done fd=%d ]", bulk_in);
    return count;
}

static ssize_t usb_write(struct transport_handle *thandle, const void *data, size_t len)
{
    ssize_t ret;
    struct transport *t = thandle->transport;
    struct usb_transport *usb_transport = container_of(t, struct usb_transport, transport);

    D(DEBUG, "about to write (fd=%d, len=%d)", usb_transport->bulk_in, len);
    ret = bulk_write(usb_transport->bulk_in, data, len);
    if (ret < 0) {
        D(ERR, "ERROR: fd = %d, ret = %zd", usb_transport->bulk_in, ret);
        return -1;
    }
    D(DEBUG, "[ usb_write done fd=%d ]", usb_transport->bulk_in);
    return ret;
}

static ssize_t bulk_read(int bulk_out, char *buf, size_t length)
{
    ssize_t ret;
    size_t n = 0;

    while (n < length) {
        size_t to_read = (length - n > READ_BUF_SIZE) ? READ_BUF_SIZE : length - n;
        ret = TEMP_FAILURE_RETRY(read(bulk_out, buf + n, to_read));
        if (ret < 0) {
            D(WARN, "[ bulk_read failed fd=%d length=%d errno=%d %s ]",
                    bulk_out, length, errno, strerror(errno));
            return ret;
        }
        n += ret;
        if (ret < (ssize_t)to_read) {
            D(VERBOSE, "bulk_read short read, ret=%zd to_read=%u n=%u length=%u",
                    ret, to_read, n, length);
            break;
        }
    }

    return n;
}

ssize_t usb_read(struct transport_handle *thandle, void *data, size_t len)
{
    ssize_t ret;
    struct transport *t = thandle->transport;
    struct usb_transport *usb_transport = container_of(t, struct usb_transport, transport);

    D(DEBUG, "about to read (fd=%d, len=%d)", usb_transport->bulk_out, len);
    ret = bulk_read(usb_transport->bulk_out, data, len);
    if (ret < 0) {
        D(ERR, "ERROR: fd = %d, ret = %zd", usb_transport->bulk_out, ret);
        return -1;
    }
    D(DEBUG, "[ usb_read done fd=%d ret=%zd]", usb_transport->bulk_out, ret);
    return ret;
}

void usb_close(struct transport_handle *thandle)
{
    int err;
    struct transport *t = thandle->transport;
    struct usb_transport *usb_transport = container_of(t, struct usb_transport, transport);

    err = ioctl(usb_transport->bulk_in, FUNCTIONFS_CLEAR_HALT);
    if (err < 0)
        D(WARN, "[ kick: source (fd=%d) clear halt failed (%d) ]", usb_transport->bulk_in, errno);

    err = ioctl(usb_transport->bulk_out, FUNCTIONFS_CLEAR_HALT);
    if (err < 0)
        D(WARN, "[ kick: sink (fd=%d) clear halt failed (%d) ]", usb_transport->bulk_out, errno);

    pthread_mutex_lock(&usb_transport->lock);
    close(usb_transport->control);
    close(usb_transport->bulk_out);
    close(usb_transport->bulk_in);
    usb_transport->control = usb_transport->bulk_out = usb_transport->bulk_in = -1;

    pthread_cond_signal(&usb_transport->notify);
    pthread_mutex_unlock(&usb_transport->lock);
}

struct transport_handle *usb_connect(struct transport *transport)
{
    int ret;
    struct usb_handle *usb_handle = calloc(sizeof(struct usb_handle), 1);
    struct usb_transport *usb_transport = container_of(transport, struct usb_transport, transport);

    pthread_mutex_lock(&usb_transport->lock);
    while (usb_transport->control != -1)
        pthread_cond_wait(&usb_transport->notify, &usb_transport->lock);
    pthread_mutex_unlock(&usb_transport->lock);

    ret = init_functionfs(usb_transport);
    if (ret < 0) {
        D(ERR, "usb connect: failed to initialize usb transport");
        return NULL;
    }

    D(DEBUG, "[ usb_thread - registering device ]");
    return &usb_handle->handle;
}

void usb_init()
{
    struct usb_transport *usb_transport = calloc(1, sizeof(struct usb_transport));

    usb_transport->transport.connect = usb_connect;
    usb_transport->transport.close = usb_close;
    usb_transport->transport.read = usb_read;
    usb_transport->transport.write = usb_write;
    usb_transport->control  = -1;
    usb_transport->bulk_out = -1;
    usb_transport->bulk_out = -1;

    pthread_cond_init(&usb_transport->notify, NULL);
    pthread_mutex_init(&usb_transport->lock, NULL);

    transport_register(&usb_transport->transport);
}


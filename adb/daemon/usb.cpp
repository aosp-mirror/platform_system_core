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

#define TRACE_TAG USB

#include "sysdeps.h"

#include <dirent.h>
#include <errno.h>
#include <linux/usb/ch9.h>
#include <linux/usb/functionfs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>

#include <android-base/logging.h>
#include <android-base/properties.h>

#include "adb.h"
#include "daemon/usb.h"
#include "transport.h"

using namespace std::chrono_literals;

#define MAX_PACKET_SIZE_FS 64
#define MAX_PACKET_SIZE_HS 512
#define MAX_PACKET_SIZE_SS 1024

#define USB_FFS_BULK_SIZE 16384

// Number of buffers needed to fit MAX_PAYLOAD, with an extra for ZLPs.
#define USB_FFS_NUM_BUFS ((MAX_PAYLOAD / USB_FFS_BULK_SIZE) + 1)

#define cpu_to_le16(x) htole16(x)
#define cpu_to_le32(x) htole32(x)

static int dummy_fd = -1;

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

static void aio_block_init(aio_block* aiob) {
    aiob->iocb.resize(USB_FFS_NUM_BUFS);
    aiob->iocbs.resize(USB_FFS_NUM_BUFS);
    aiob->events.resize(USB_FFS_NUM_BUFS);
    aiob->num_submitted = 0;
    for (unsigned i = 0; i < USB_FFS_NUM_BUFS; i++) {
        aiob->iocbs[i] = &aiob->iocb[i];
    }
}

static int getMaxPacketSize(int ffs_fd) {
    usb_endpoint_descriptor desc;
    if (ioctl(ffs_fd, FUNCTIONFS_ENDPOINT_DESC, reinterpret_cast<unsigned long>(&desc))) {
        D("[ could not get endpoint descriptor! (%d) ]", errno);
        return MAX_PACKET_SIZE_HS;
    } else {
        return desc.wMaxPacketSize;
    }
}

bool init_functionfs(struct usb_handle* h) {
    LOG(INFO) << "initializing functionfs";

    ssize_t ret;
    struct desc_v1 v1_descriptor;
    struct desc_v2 v2_descriptor;

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

    if (h->control < 0) { // might have already done this before
        LOG(INFO) << "opening control endpoint " << USB_FFS_ADB_EP0;
        h->control = adb_open(USB_FFS_ADB_EP0, O_WRONLY);
        if (h->control < 0) {
            PLOG(ERROR) << "cannot open control endpoint " << USB_FFS_ADB_EP0;
            goto err;
        }

        ret = adb_write(h->control, &v2_descriptor, sizeof(v2_descriptor));
        if (ret < 0) {
            v1_descriptor.header.magic = cpu_to_le32(FUNCTIONFS_DESCRIPTORS_MAGIC);
            v1_descriptor.header.length = cpu_to_le32(sizeof(v1_descriptor));
            v1_descriptor.header.fs_count = 3;
            v1_descriptor.header.hs_count = 3;
            v1_descriptor.fs_descs = fs_descriptors;
            v1_descriptor.hs_descs = hs_descriptors;
            D("[ %s: Switching to V1_descriptor format errno=%d ]", USB_FFS_ADB_EP0, errno);
            ret = adb_write(h->control, &v1_descriptor, sizeof(v1_descriptor));
            if (ret < 0) {
                D("[ %s: write descriptors failed: errno=%d ]", USB_FFS_ADB_EP0, errno);
                goto err;
            }
        }

        ret = adb_write(h->control, &strings, sizeof(strings));
        if (ret < 0) {
            D("[ %s: writing strings failed: errno=%d]", USB_FFS_ADB_EP0, errno);
            goto err;
        }
        //Signal only when writing the descriptors to ffs
        android::base::SetProperty("sys.usb.ffs.ready", "1");
    }

    h->bulk_out = adb_open(USB_FFS_ADB_OUT, O_RDONLY);
    if (h->bulk_out < 0) {
        PLOG(ERROR) << "cannot open bulk-out endpoint " << USB_FFS_ADB_OUT;
        goto err;
    }

    h->bulk_in = adb_open(USB_FFS_ADB_IN, O_WRONLY);
    if (h->bulk_in < 0) {
        PLOG(ERROR) << "cannot open bulk-in endpoint " << USB_FFS_ADB_IN;
        goto err;
    }

    memset(&h->read_aiob.ctx, 0, sizeof(h->read_aiob.ctx));
    memset(&h->write_aiob.ctx, 0, sizeof(h->write_aiob.ctx));
    if (io_setup(USB_FFS_NUM_BUFS, &h->read_aiob.ctx) ||
        io_setup(USB_FFS_NUM_BUFS, &h->write_aiob.ctx)) {
        D("[ aio: got error on io_setup (%d) ]", errno);
    }

    h->read_aiob.fd = h->bulk_out;
    h->write_aiob.fd = h->bulk_in;
    return true;

err:
    if (h->bulk_in > 0) {
        adb_close(h->bulk_in);
        h->bulk_in = -1;
    }
    if (h->bulk_out > 0) {
        adb_close(h->bulk_out);
        h->bulk_out = -1;
    }
    if (h->control > 0) {
        adb_close(h->control);
        h->control = -1;
    }
    return false;
}

static void usb_ffs_open_thread(void* x) {
    struct usb_handle* usb = (struct usb_handle*)x;

    adb_thread_setname("usb ffs open");

    while (true) {
        // wait until the USB device needs opening
        std::unique_lock<std::mutex> lock(usb->lock);
        while (!usb->open_new_connection) {
            usb->notify.wait(lock);
        }
        usb->open_new_connection = false;
        lock.unlock();

        while (true) {
            if (init_functionfs(usb)) {
                LOG(INFO) << "functionfs successfully initialized";
                break;
            }
            std::this_thread::sleep_for(1s);
        }

        LOG(INFO) << "registering usb transport";
        register_usb_transport(usb, 0, 0, 1);
    }

    // never gets here
    abort();
}

static int usb_ffs_write(usb_handle* h, const void* data, int len) {
    D("about to write (fd=%d, len=%d)", h->bulk_in, len);

    const char* buf = static_cast<const char*>(data);
    while (len > 0) {
        int write_len = std::min(USB_FFS_BULK_SIZE, len);
        int n = adb_write(h->bulk_in, buf, write_len);
        if (n < 0) {
            D("ERROR: fd = %d, n = %d: %s", h->bulk_in, n, strerror(errno));
            return -1;
        }
        buf += n;
        len -= n;
    }

    D("[ done fd=%d ]", h->bulk_in);
    return 0;
}

static int usb_ffs_read(usb_handle* h, void* data, int len) {
    D("about to read (fd=%d, len=%d)", h->bulk_out, len);

    char* buf = static_cast<char*>(data);
    while (len > 0) {
        int read_len = std::min(USB_FFS_BULK_SIZE, len);
        int n = adb_read(h->bulk_out, buf, read_len);
        if (n < 0) {
            D("ERROR: fd = %d, n = %d: %s", h->bulk_out, n, strerror(errno));
            return -1;
        }
        buf += n;
        len -= n;
    }

    D("[ done fd=%d ]", h->bulk_out);
    return 0;
}

static int usb_ffs_do_aio(usb_handle* h, const void* data, int len, bool read) {
    aio_block* aiob = read ? &h->read_aiob : &h->write_aiob;
    bool zero_packet = false;

    int num_bufs = len / USB_FFS_BULK_SIZE + (len % USB_FFS_BULK_SIZE == 0 ? 0 : 1);
    const char* cur_data = reinterpret_cast<const char*>(data);
    int packet_size = getMaxPacketSize(aiob->fd);

    if (posix_madvise(const_cast<void*>(data), len, POSIX_MADV_SEQUENTIAL | POSIX_MADV_WILLNEED) <
        0) {
        D("[ Failed to madvise: %d ]", errno);
    }

    for (int i = 0; i < num_bufs; i++) {
        int buf_len = std::min(len, USB_FFS_BULK_SIZE);
        io_prep(&aiob->iocb[i], aiob->fd, cur_data, buf_len, 0, read);

        len -= buf_len;
        cur_data += buf_len;

        if (len == 0 && buf_len % packet_size == 0 && read) {
            // adb does not expect the device to send a zero packet after data transfer,
            // but the host *does* send a zero packet for the device to read.
            zero_packet = true;
        }
    }
    if (zero_packet) {
        io_prep(&aiob->iocb[num_bufs], aiob->fd, reinterpret_cast<const void*>(cur_data),
                packet_size, 0, read);
        num_bufs += 1;
    }

    if (io_submit(aiob->ctx, num_bufs, aiob->iocbs.data()) < num_bufs) {
        D("[ aio: got error submitting %s (%d) ]", read ? "read" : "write", errno);
        return -1;
    }
    if (TEMP_FAILURE_RETRY(
            io_getevents(aiob->ctx, num_bufs, num_bufs, aiob->events.data(), nullptr)) < num_bufs) {
        D("[ aio: got error waiting %s (%d) ]", read ? "read" : "write", errno);
        return -1;
    }
    for (int i = 0; i < num_bufs; i++) {
        if (aiob->events[i].res < 0) {
            errno = aiob->events[i].res;
            D("[ aio: got error event on %s (%d) ]", read ? "read" : "write", errno);
            return -1;
        }
    }
    return 0;
}

static int usb_ffs_aio_read(usb_handle* h, void* data, int len) {
    return usb_ffs_do_aio(h, data, len, true);
}

static int usb_ffs_aio_write(usb_handle* h, const void* data, int len) {
    return usb_ffs_do_aio(h, data, len, false);
}

static void usb_ffs_kick(usb_handle* h) {
    int err;

    err = ioctl(h->bulk_in, FUNCTIONFS_CLEAR_HALT);
    if (err < 0) {
        D("[ kick: source (fd=%d) clear halt failed (%d) ]", h->bulk_in, errno);
    }

    err = ioctl(h->bulk_out, FUNCTIONFS_CLEAR_HALT);
    if (err < 0) {
        D("[ kick: sink (fd=%d) clear halt failed (%d) ]", h->bulk_out, errno);
    }

    // don't close ep0 here, since we may not need to reinitialize it with
    // the same descriptors again. if however ep1/ep2 fail to re-open in
    // init_functionfs, only then would we close and open ep0 again.
    // Ditto the comment in usb_adb_kick.
    h->kicked = true;
    TEMP_FAILURE_RETRY(dup2(dummy_fd, h->bulk_out));
    TEMP_FAILURE_RETRY(dup2(dummy_fd, h->bulk_in));
}

static void usb_ffs_close(usb_handle* h) {
    LOG(INFO) << "closing functionfs transport";

    h->kicked = false;
    adb_close(h->bulk_out);
    adb_close(h->bulk_in);
    io_destroy(h->read_aiob.ctx);
    io_destroy(h->write_aiob.ctx);

    // Notify usb_adb_open_thread to open a new connection.
    h->lock.lock();
    h->open_new_connection = true;
    h->lock.unlock();
    h->notify.notify_one();
}

static void usb_ffs_init() {
    D("[ usb_init - using FunctionFS ]");

    usb_handle* h = new usb_handle();

    if (android::base::GetBoolProperty("sys.usb.ffs.aio_compat", false)) {
        // Devices on older kernels (< 3.18) will not have aio support for ffs
        // unless backported. Fall back on the non-aio functions instead.
        h->write = usb_ffs_write;
        h->read = usb_ffs_read;
    } else {
        h->write = usb_ffs_aio_write;
        h->read = usb_ffs_aio_read;
        aio_block_init(&h->read_aiob);
        aio_block_init(&h->write_aiob);
    }
    h->kick = usb_ffs_kick;
    h->close = usb_ffs_close;

    D("[ usb_init - starting thread ]");
    std::thread(usb_ffs_open_thread, h).detach();
}

void usb_init() {
    dummy_fd = adb_open("/dev/null", O_WRONLY);
    CHECK_NE(dummy_fd, -1);
    usb_ffs_init();
}

int usb_write(usb_handle* h, const void* data, int len) {
    return h->write(h, data, len);
}

int usb_read(usb_handle* h, void* data, int len) {
    return h->read(h, data, len);
}

int usb_close(usb_handle* h) {
    h->close(h);
    return 0;
}

void usb_kick(usb_handle* h) {
    h->kick(h);
}

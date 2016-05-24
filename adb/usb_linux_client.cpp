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

#include <cutils/properties.h>
#include <dirent.h>
#include <errno.h>
#include <linux/usb/ch9.h>
#include <linux/usb/functionfs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>

#include <android-base/logging.h>

#include "adb.h"
#include "transport.h"

#define MAX_PACKET_SIZE_FS	64
#define MAX_PACKET_SIZE_HS	512
#define MAX_PACKET_SIZE_SS	1024

// Writes larger than 16k fail on some devices (seed with 3.10.49-g209ea2f in particular).
#define USB_FFS_MAX_WRITE 16384

// The kernel allocates a contiguous buffer for reads, which can fail for large ones due to
// fragmentation. 16k chosen arbitrarily to match the write limit.
#define USB_FFS_MAX_READ 16384

#define cpu_to_le16(x)  htole16(x)
#define cpu_to_le32(x)  htole32(x)

static int dummy_fd = -1;

struct usb_handle
{
    adb_cond_t notify;
    adb_mutex_t lock;
    bool open_new_connection;
    std::atomic<bool> kicked;

    int (*write)(usb_handle *h, const void *data, int len);
    int (*read)(usb_handle *h, void *data, int len);
    void (*kick)(usb_handle *h);
    void (*close)(usb_handle *h);

    // Legacy f_adb
    int fd;

    // FunctionFS
    int control;
    int bulk_out; /* "out" from the host's perspective => source for adbd */
    int bulk_in;  /* "in" from the host's perspective => sink for adbd */
};

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

static void usb_adb_open_thread(void* x) {
    struct usb_handle *usb = (struct usb_handle *)x;
    int fd;

    adb_thread_setname("usb open");

    while (true) {
        // wait until the USB device needs opening
        adb_mutex_lock(&usb->lock);
        while (!usb->open_new_connection) {
            adb_cond_wait(&usb->notify, &usb->lock);
        }
        usb->open_new_connection = false;
        adb_mutex_unlock(&usb->lock);

        D("[ usb_thread - opening device ]");
        do {
            /* XXX use inotify? */
            fd = unix_open("/dev/android_adb", O_RDWR);
            if (fd < 0) {
                // to support older kernels
                fd = unix_open("/dev/android", O_RDWR);
            }
            if (fd < 0) {
                adb_sleep_ms(1000);
            }
        } while (fd < 0);
        D("[ opening device succeeded ]");

        close_on_exec(fd);
        usb->fd = fd;

        D("[ usb_thread - registering device ]");
        register_usb_transport(usb, 0, 0, 1);
    }

    // never gets here
    abort();
}

static int usb_adb_write(usb_handle *h, const void *data, int len)
{
    int n;

    D("about to write (fd=%d, len=%d)", h->fd, len);
    n = unix_write(h->fd, data, len);
    if(n != len) {
        D("ERROR: fd = %d, n = %d, errno = %d (%s)",
            h->fd, n, errno, strerror(errno));
        return -1;
    }
    if (h->kicked) {
        D("usb_adb_write finished due to kicked");
        return -1;
    }
    D("[ done fd=%d ]", h->fd);
    return 0;
}

static int usb_adb_read(usb_handle *h, void *data, int len)
{
    D("about to read (fd=%d, len=%d)", h->fd, len);
    while (len > 0) {
        // The kernel implementation of adb_read in f_adb.c doesn't support
        // reads larger then 4096 bytes. Read the data in 4096 byte chunks to
        // avoid the issue. (The ffs implementation doesn't have this limit.)
        int bytes_to_read = len < 4096 ? len : 4096;
        int n = unix_read(h->fd, data, bytes_to_read);
        if (n != bytes_to_read) {
            D("ERROR: fd = %d, n = %d, errno = %d (%s)",
                h->fd, n, errno, strerror(errno));
            return -1;
        }
        if (h->kicked) {
            D("usb_adb_read finished due to kicked");
            return -1;
        }
        len -= n;
        data = ((char*)data) + n;
    }
    D("[ done fd=%d ]", h->fd);
    return 0;
}

static void usb_adb_kick(usb_handle *h) {
    D("usb_kick");
    // Other threads may be calling usb_adb_read/usb_adb_write at the same time.
    // If we close h->fd, the file descriptor will be reused to open other files,
    // and the read/write thread may operate on the wrong file. So instead
    // we set the kicked flag and reopen h->fd to a dummy file here. After read/write
    // threads finish, we close h->fd in usb_adb_close().
    h->kicked = true;
    TEMP_FAILURE_RETRY(dup2(dummy_fd, h->fd));
}

static void usb_adb_close(usb_handle *h) {
    h->kicked = false;
    adb_close(h->fd);
    // Notify usb_adb_open_thread to open a new connection.
    adb_mutex_lock(&h->lock);
    h->open_new_connection = true;
    adb_cond_signal(&h->notify);
    adb_mutex_unlock(&h->lock);
}

static void usb_adb_init()
{
    usb_handle* h = reinterpret_cast<usb_handle*>(calloc(1, sizeof(usb_handle)));
    if (h == nullptr) fatal("couldn't allocate usb_handle");

    h->write = usb_adb_write;
    h->read = usb_adb_read;
    h->kick = usb_adb_kick;
    h->close = usb_adb_close;
    h->kicked = false;
    h->fd = -1;

    h->open_new_connection = true;
    adb_cond_init(&h->notify, 0);
    adb_mutex_init(&h->lock, 0);

    // Open the file /dev/android_adb_enable to trigger
    // the enabling of the adb USB function in the kernel.
    // We never touch this file again - just leave it open
    // indefinitely so the kernel will know when we are running
    // and when we are not.
    int fd = unix_open("/dev/android_adb_enable", O_RDWR);
    if (fd < 0) {
       D("failed to open /dev/android_adb_enable");
    } else {
        close_on_exec(fd);
    }

    D("[ usb_init - starting thread ]");
    if (!adb_thread_create(usb_adb_open_thread, h)) {
        fatal_errno("cannot create usb thread");
    }
}


static bool init_functionfs(struct usb_handle *h)
{
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

    D("OPENING %s", USB_FFS_ADB_EP0);
    h->control = adb_open(USB_FFS_ADB_EP0, O_RDWR);
    if (h->control < 0) {
        D("[ %s: cannot open control endpoint: errno=%d]", USB_FFS_ADB_EP0, errno);
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

    h->bulk_out = adb_open(USB_FFS_ADB_OUT, O_RDWR);
    if (h->bulk_out < 0) {
        D("[ %s: cannot open bulk-out ep: errno=%d ]", USB_FFS_ADB_OUT, errno);
        goto err;
    }

    h->bulk_in = adb_open(USB_FFS_ADB_IN, O_RDWR);
    if (h->bulk_in < 0) {
        D("[ %s: cannot open bulk-in ep: errno=%d ]", USB_FFS_ADB_IN, errno);
        goto err;
    }

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
    struct usb_handle *usb = (struct usb_handle *)x;

    adb_thread_setname("usb ffs open");

    while (true) {
        // wait until the USB device needs opening
        adb_mutex_lock(&usb->lock);
        while (!usb->open_new_connection) {
            adb_cond_wait(&usb->notify, &usb->lock);
        }
        usb->open_new_connection = false;
        adb_mutex_unlock(&usb->lock);

        while (true) {
            if (init_functionfs(usb)) {
                break;
            }
            adb_sleep_ms(1000);
        }
        property_set("sys.usb.ffs.ready", "1");

        D("[ usb_thread - registering device ]");
        register_usb_transport(usb, 0, 0, 1);
    }

    // never gets here
    abort();
}

static int usb_ffs_write(usb_handle* h, const void* data, int len) {
    D("about to write (fd=%d, len=%d)", h->bulk_in, len);

    const char* buf = static_cast<const char*>(data);
    while (len > 0) {
        int write_len = std::min(USB_FFS_MAX_WRITE, len);
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
        int read_len = std::min(USB_FFS_MAX_READ, len);
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

static void usb_ffs_kick(usb_handle *h)
{
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

static void usb_ffs_close(usb_handle *h) {
    h->kicked = false;
    adb_close(h->bulk_out);
    adb_close(h->bulk_in);
    adb_close(h->control);
    // Notify usb_adb_open_thread to open a new connection.
    adb_mutex_lock(&h->lock);
    h->open_new_connection = true;
    adb_cond_signal(&h->notify);
    adb_mutex_unlock(&h->lock);
}

static void usb_ffs_init()
{
    D("[ usb_init - using FunctionFS ]");

    usb_handle* h = reinterpret_cast<usb_handle*>(calloc(1, sizeof(usb_handle)));
    if (h == nullptr) fatal("couldn't allocate usb_handle");

    h->write = usb_ffs_write;
    h->read = usb_ffs_read;
    h->kick = usb_ffs_kick;
    h->close = usb_ffs_close;
    h->kicked = false;
    h->control = -1;
    h->bulk_out = -1;
    h->bulk_out = -1;

    h->open_new_connection = true;
    adb_cond_init(&h->notify, 0);
    adb_mutex_init(&h->lock, 0);

    D("[ usb_init - starting thread ]");
    if (!adb_thread_create(usb_ffs_open_thread, h)) {
        fatal_errno("[ cannot create usb thread ]\n");
    }
}

void usb_init()
{
    dummy_fd = adb_open("/dev/null", O_WRONLY);
    CHECK_NE(dummy_fd, -1);
    if (access(USB_FFS_ADB_EP0, F_OK) == 0)
        usb_ffs_init();
    else
        usb_adb_init();
}

int usb_write(usb_handle *h, const void *data, int len)
{
    return h->write(h, data, len);
}

int usb_read(usb_handle *h, void *data, int len)
{
    return h->read(h, data, len);
}
int usb_close(usb_handle *h)
{
    h->close(h);
    return 0;
}

void usb_kick(usb_handle *h)
{
    h->kick(h);
}

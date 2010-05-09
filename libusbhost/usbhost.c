/*
 * Copyright (C) 2010 The Android Open Source Project
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/inotify.h>
#include <dirent.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <pthread.h>

#include <linux/usbdevice_fs.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
#include <linux/usb/ch9.h>
#else
#include <linux/usb_ch9.h>
#endif
#include <asm/byteorder.h>

#include "usbhost/usbhost.h"

#define USB_FS_DIR "/dev/bus/usb"

#if 0
#define D printf
#else
#define D(...)
#endif

struct usb_device {
    char dev_name[64];
    unsigned char desc[256];
    int desc_length;
    int fd;
    int writeable;
};

struct usb_endpoint
{
    struct usb_device *dev;
    struct usb_endpoint_descriptor  desc;
    struct usbdevfs_urb urb;
};

static usb_device_added_cb s_added_cb;
static usb_device_removed_cb s_removed_cb;

static inline int badname(const char *name)
{
    while(*name) {
        if(!isdigit(*name++)) return 1;
    }
    return 0;
}

static void find_existing_devices()
{
    char busname[32], devname[32];
    DIR *busdir , *devdir ;
    struct dirent *de;

    busdir = opendir(USB_FS_DIR);
    if(busdir == 0) return;

    while((de = readdir(busdir)) != 0) {
        if(badname(de->d_name)) continue;

        snprintf(busname, sizeof busname, "%s/%s", USB_FS_DIR, de->d_name);
        devdir = opendir(busname);
        if(devdir == 0) continue;

        while((de = readdir(devdir))) {
            if(badname(de->d_name)) continue;

            snprintf(devname, sizeof devname, "%s/%s", busname, de->d_name);
            s_added_cb(devname);
        } // end of devdir while
        closedir(devdir);
    } //end of busdir while
    closedir(busdir);
}

static void* device_discovery_thread(void* unused)
{
    struct inotify_event* event;
    char event_buf[512];
    char path[100];
    int i, fd, ret;
    int wd, wds[10];
    int wd_count = sizeof(wds) / sizeof(wds[0]);

    D("Created device discovery thread\n");

    fd = inotify_init();
    if (fd < 0) {
        fprintf(stderr, "inotify_init failed\n");
        return NULL;
    }

    /* watch for files added and deleted within USB_FS_DIR */
    memset(wds, 0, sizeof(wds));
    /* watch the root for new subdirectories */
    wds[0] = inotify_add_watch(fd, USB_FS_DIR, IN_CREATE | IN_DELETE);
    if (wds[0] < 0) {
        fprintf(stderr, "inotify_add_watch failed\n");
        return NULL;
    }

    /* watch existing subdirectories of USB_FS_DIR */
    for (i = 1; i < wd_count; i++) {
        snprintf(path, sizeof(path), "%s/%03d", USB_FS_DIR, i);
        ret = inotify_add_watch(fd, path, IN_CREATE | IN_DELETE);
        if (ret > 0)
            wds[i] = ret;
    }

    /* check for existing devices first, after we have inotify set up */
    if (s_added_cb)
        find_existing_devices();

    while (1) {
        ret = read(fd, event_buf, sizeof(event_buf));
        if (ret >= (int)sizeof(struct inotify_event)) {
            event = (struct inotify_event *)event_buf;
            wd = event->wd;
            if (wd == wds[0]) {
                i = atoi(event->name);
                snprintf(path, sizeof(path), "%s/%s", USB_FS_DIR, event->name);
                D("new subdirectory %s: index: %d\n", path, i);
                if (i > 0 && i < wd_count) {
                ret = inotify_add_watch(fd, path, IN_CREATE | IN_DELETE);
                if (ret > 0)
                    wds[i] = ret;
                }
            } else {
                for (i = 1; i < wd_count; i++) {
                    if (wd == wds[i]) {
                        snprintf(path, sizeof(path), "%s/%03d/%s", USB_FS_DIR, i, event->name);
                        if (event->mask == IN_CREATE) {
                            D("new device %s\n", path);
                            if (s_added_cb)
                                s_added_cb(path);
                        } else if (event->mask == IN_DELETE) {
                            D("gone device %s\n", path);
                            if (s_removed_cb)
                                s_removed_cb(path);
                        }
                    }
                }
            }
        }
    }
    return NULL;
}

int usb_host_init(usb_device_added_cb added_cb, usb_device_removed_cb removed_cb)
{
    pthread_t tid;

    s_added_cb = added_cb;
    s_removed_cb = removed_cb;

    if (added_cb || removed_cb) {
        pthread_attr_t   attr;

        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        return pthread_create(&tid, &attr, device_discovery_thread, NULL);
    }
    else
        return 0;
}

struct usb_device *usb_device_open(const char *dev_name)
{
    struct usb_device *device = calloc(1, sizeof(struct usb_device));
    int fd, length, did_retry = 0;

    strcpy(device->dev_name, dev_name);
    device->writeable = 1;

retry:
    fd = open(dev_name, O_RDWR);
    if (fd < 0) {
        /* if we fail, see if have read-only access */
        fd = open(dev_name, O_RDONLY);
        if (fd < 0 && errno == EACCES && !did_retry) {
            /* work around race condition between inotify and permissions management */
            sleep(1);
            did_retry = 1;
            goto retry;
        }

        if (fd < 0) goto fail;
        device->writeable = 0;
        D("[ usb open read-only %s fd = %d]\n", dev_name, fd);
    }

    length = read(fd, device->desc, sizeof(device->desc));
    if (length < 0)
        goto fail;

    device->fd = fd;
    device->desc_length = length;
    return device;
fail:
    close(fd);
    free(device);
    return NULL;
}

void usb_device_close(struct usb_device *device)
{
    close(device->fd);
    free(device);
}

const char* usb_device_get_name(struct usb_device *device)
{
    return device->dev_name;
}

uint16_t usb_device_get_vendor_id(struct usb_device *device)
{
    struct usb_device_descriptor* desc = (struct usb_device_descriptor*)device->desc;
    return __le16_to_cpu(desc->idVendor);
}

uint16_t usb_device_get_product_id(struct usb_device *device)
{
    struct usb_device_descriptor* desc = (struct usb_device_descriptor*)device->desc;
    return __le16_to_cpu(desc->idProduct);
}

char* usb_device_get_string(struct usb_device *device, int id)
{
    char string[256];
    struct usbdevfs_ctrltransfer  ctrl;
    __u16 buffer[128];
    __u16 languages[128];
    int i, result;
    int languageCount = 0;

    string[0] = 0;

    // reading the string requires read/write permission
    if (!device->writeable) {
        int fd = open(device->dev_name, O_RDWR);
        if (fd > 0) {
            close(device->fd);
            device->fd = fd;
            device->writeable = 1;
        } else {
            return NULL;
        }
    }

    memset(languages, 0, sizeof(languages));
    memset(&ctrl, 0, sizeof(ctrl));

    // read list of supported languages
    ctrl.bRequestType = USB_DIR_IN|USB_TYPE_STANDARD|USB_RECIP_DEVICE;
    ctrl.bRequest = USB_REQ_GET_DESCRIPTOR;
    ctrl.wValue = (USB_DT_STRING << 8) | 0;
    ctrl.wIndex = 0;
    ctrl.wLength = sizeof(languages);
    ctrl.data = languages;

    result = ioctl(device->fd, USBDEVFS_CONTROL, &ctrl);
    if (result > 0)
        languageCount = (result - 2) / 2;

    for (i = 1; i <= languageCount; i++) {
        memset(buffer, 0, sizeof(buffer));
        memset(&ctrl, 0, sizeof(ctrl));

        ctrl.bRequestType = USB_DIR_IN|USB_TYPE_STANDARD|USB_RECIP_DEVICE;
        ctrl.bRequest = USB_REQ_GET_DESCRIPTOR;
        ctrl.wValue = (USB_DT_STRING << 8) | id;
        ctrl.wIndex = languages[i];
        ctrl.wLength = sizeof(buffer);
        ctrl.data = buffer;

        result = ioctl(device->fd, USBDEVFS_CONTROL, &ctrl);
        if (result > 0) {
            int i;
            // skip first word, and copy the rest to the string, changing shorts to bytes.
            result /= 2;
            for (i = 1; i < result; i++)
                string[i - 1] = buffer[i];
            string[i - 1] = 0;
            return strdup(string);
        }
    }

    return NULL;
}

char* usb_device_get_manufacturer_name(struct usb_device *device)
{
    struct usb_device_descriptor *desc = (struct usb_device_descriptor *)device->desc;

    if (desc->iManufacturer)
        return usb_device_get_string(device, desc->iManufacturer);
    else
        return NULL;
}

char* usb_device_get_product_name(struct usb_device *device)
{
    struct usb_device_descriptor *desc = (struct usb_device_descriptor *)device->desc;

    if (desc->iProduct)
        return usb_device_get_string(device, desc->iProduct);
    else
        return NULL;
}

char* usb_device_get_serial(struct usb_device *device)
{
    struct usb_device_descriptor *desc = (struct usb_device_descriptor *)device->desc;

    if (desc->iSerialNumber)
        return usb_device_get_string(device, desc->iSerialNumber);
    else
        return NULL;
}

int usb_device_is_writeable(struct usb_device *device)
{
    return device->writeable;
}

void usb_descriptor_iter_init(struct usb_device *device, struct usb_descriptor_iter *iter)
{
    iter->config = device->desc;
    iter->config_end = device->desc + device->desc_length;
    iter->curr_desc = device->desc;
}

struct usb_descriptor_header *usb_descriptor_iter_next(struct usb_descriptor_iter *iter)
{
    struct usb_descriptor_header* next;
    if (iter->curr_desc >= iter->config_end)
        return NULL;
    next = (struct usb_descriptor_header*)iter->curr_desc;
    iter->curr_desc += next->bLength;
    return next;
}

int usb_device_claim_interface(struct usb_device *device, unsigned int interface)
{
    return ioctl(device->fd, USBDEVFS_CLAIMINTERFACE, &interface);
}

int usb_device_release_interface(struct usb_device *device, unsigned int interface)
{
    return ioctl(device->fd, USBDEVFS_RELEASEINTERFACE, &interface);
}

struct usb_endpoint *usb_endpoint_open(struct usb_device *dev,
        const struct usb_endpoint_descriptor *desc)
{
    struct usb_endpoint *ep = calloc(1, sizeof(struct usb_endpoint));
    memcpy(&ep->desc, desc, sizeof(ep->desc));
    ep->dev = dev;
    return ep;
}

void usb_endpoint_close(struct usb_endpoint *ep)
{
    // cancel IO here?
    free(ep);
}

int usb_endpoint_queue(struct usb_endpoint *ep, void *data, int len)
{
    struct usbdevfs_urb *urb = &ep->urb;
    int res;

    D("usb_endpoint_queue\n");
    memset(urb, 0, sizeof(*urb));
    urb->type = USBDEVFS_URB_TYPE_BULK;
    urb->endpoint = ep->desc.bEndpointAddress;
    urb->status = -1;
    urb->buffer = data;
    urb->buffer_length = len;

    do {
        res = ioctl(ep->dev->fd, USBDEVFS_SUBMITURB, urb);
    } while((res < 0) && (errno == EINTR));

    return res;
}

int usb_endpoint_wait(struct usb_device *dev, int *out_ep_num)
{
    struct usbdevfs_urb *out = NULL;
    int res;

    while (1) {
        res = ioctl(dev->fd, USBDEVFS_REAPURB, &out);
        D("USBDEVFS_REAPURB returned %d\n", res);
        if (res < 0) {
            if(errno == EINTR) {
                continue;
            }
            D("[ reap urb - error ]\n");
            *out_ep_num = -1;
        } else {
            D("[ urb @%p status = %d, actual = %d ]\n",
                out, out->status, out->actual_length);
            res = out->actual_length;
            *out_ep_num = out->endpoint;
        }
        break;
    }
    return res;
}

int usb_endpoint_cancel(struct usb_endpoint *ep)
{
    return ioctl(ep->dev->fd, USBDEVFS_DISCARDURB, &ep->urb);
}

int usb_endpoint_number(struct usb_endpoint *ep)
{
    return ep->desc.bEndpointAddress;
}

int usb_endpoint_max_packet(struct usb_endpoint *ep)
{
    return __le16_to_cpu(ep->desc.wMaxPacketSize);
}


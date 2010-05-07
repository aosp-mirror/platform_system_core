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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <usbhost/usbhost.h>
#include <linux/usbdevice_fs.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
#include <linux/usb/ch9.h>
#else
#include <linux/usb_ch9.h>
#endif

#include "sysdeps.h"

#define   TRACE_TAG  TRACE_USB
#include "adb.h"


/* usb scan debugging is waaaay too verbose */
#define DBGX(x...)

static adb_mutex_t usb_lock = ADB_MUTEX_INITIALIZER;

struct usb_handle
{
    usb_handle *prev;
    usb_handle *next;

    struct usb_device *device;
    struct usb_endpoint *ep_in;
    struct usb_endpoint *ep_out;

    adb_cond_t notify_in;
    adb_cond_t notify_out;
    adb_mutex_t lock;

    int read_result, write_result;
    int zero_mask;
    int dead;

    // Thread ID for our reaper thread
    pthread_t reaper_thread;
};

static usb_handle handle_list = {
    .prev = &handle_list,
    .next = &handle_list,
};

static int known_device(const char *dev_name)
{
    usb_handle *usb;

    adb_mutex_lock(&usb_lock);
    for (usb = handle_list.next; usb != &handle_list; usb = usb->next) {
        if (!strcmp(usb_device_get_name(usb->device), dev_name)) {
            adb_mutex_unlock(&usb_lock);
            return 1;
        }
    }
    adb_mutex_unlock(&usb_lock);
    return 0;
}

static void kick_disconnected_device(const char *devname)
{
    usb_handle *usb;

    adb_mutex_lock(&usb_lock);
    /* kick the device if it is in our list */
    for (usb = handle_list.next; usb != &handle_list; usb = usb->next) {
        if (!strcmp(devname, usb_device_get_name(usb->device)))
            usb_kick(usb);
    }
    adb_mutex_unlock(&usb_lock);

}

static void* reaper_thread(void* arg)
{
    struct usb_handle* h = (struct usb_handle *)arg;
    int ep_in = usb_endpoint_number(h->ep_in);
    int ep_out = usb_endpoint_number(h->ep_out);
    int reaped_ep, res;

    while (1) {
        D("[ reap urb - wait ]\n");
        adb_mutex_unlock(&h->lock);
        res = usb_endpoint_wait(h->device, &reaped_ep);
        adb_mutex_lock(&h->lock);
        if(h->dead) {
            res = -1;
            break;
        }

        D("[ reaped ep %d ret = %d ]\n", reaped_ep, res);

        if (reaped_ep == ep_in) {
            D("[ reap urb - IN complete ]\n");
            h->read_result = res;
            adb_cond_broadcast(&h->notify_in);
        }
        if (reaped_ep == ep_out) {
            D("[ reap urb - OUT compelete ]\n");
            h->write_result = res;
            adb_cond_broadcast(&h->notify_out);
        }
    }

    return NULL;
}

static void register_device(struct usb_device *device, int interface,
        struct usb_endpoint *ep_in, struct usb_endpoint *ep_out)
{
    usb_handle* usb = 0;
    int ret = 0;
    int writeable;
    char *serial;
    pthread_attr_t   attr;
    const char* dev_name = usb_device_get_name(device);

        /* Since Linux will not reassign the device ID (and dev_name)
        ** as long as the device is open, we can add to the list here
        ** once we open it and remove from the list when we're finally
        ** closed and everything will work out fine.
        **
        ** If we have a usb_handle on the list 'o handles with a matching
        ** name, we have no further work to do.
        */
    adb_mutex_lock(&usb_lock);
    for (usb = handle_list.next; usb != &handle_list; usb = usb->next) {
        if (!strcmp(usb_device_get_name(usb->device), dev_name)) {
            adb_mutex_unlock(&usb_lock);
            return;
        }
    }
    adb_mutex_unlock(&usb_lock);

    usb = calloc(1, sizeof(usb_handle));
    adb_cond_init(&usb->notify_in, 0);
    adb_cond_init(&usb->notify_out, 0);
    adb_mutex_init(&usb->lock, 0);

    usb->device = device;
    usb->ep_in = ep_in;
    usb->ep_out = ep_out;
    usb->zero_mask = usb_endpoint_max_packet(usb->ep_out) - 1;

    D("[ usb open %s ]\n", dev_name);
    writeable = usb_device_is_writeable(device);
    if (writeable) {
        ret = usb_device_claim_interface(device, interface);
        if(ret != 0) goto fail;
    }

        /* add to the end of the active handles */
    adb_mutex_lock(&usb_lock);
    usb->next = &handle_list;
    usb->prev = handle_list.prev;
    usb->prev->next = usb;
    usb->next->prev = usb;
    adb_mutex_unlock(&usb_lock);

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&usb->reaper_thread, &attr, reaper_thread, usb);

    serial = usb_device_get_serial(device);
    register_usb_transport(usb, serial, writeable);
    if (serial)
        free(serial);
    return;

fail:
    D("[ usb open %s error=%d, err_str = %s]\n",
        dev_name,  errno, strerror(errno));
    if (usb->ep_in)
        usb_endpoint_close(usb->ep_in);
    if (usb->ep_out)
        usb_endpoint_close(usb->ep_out);
    if(device) {
        usb_device_close(device);
    }
    free(usb);
}

static void check_usb_device(const char *devname) {
    struct usb_device *device;
    struct usb_descriptor_iter iter;
    struct usb_descriptor_header* header;
    struct usb_interface_descriptor* interface;
    struct usb_endpoint_descriptor *ep1, *ep2;
    struct usb_endpoint *ep_in = NULL, *ep_out = NULL;
    uint16_t vid, pid;

    if(known_device(devname)) {
        DBGX("skipping %s\n", devname);
        return;
    }

    device = usb_device_open(devname);
    if (!device) return;

    vid = usb_device_get_vendor_id(device);
    pid = usb_device_get_product_id(device);
    DBGX("[ %s is V:%04x P:%04x ]\n", devname, vid, pid);

    // loop through all the descriptors and look for the ADB interface
    usb_descriptor_iter_init(device, &iter);

    while ((header = usb_descriptor_iter_next(&iter)) != NULL) {
        if (header->bDescriptorType == USB_DT_INTERFACE) {
            interface = (struct usb_interface_descriptor *)header;

            DBGX("bInterfaceClass: %d,  bInterfaceSubClass: %d,"
                 "bInterfaceProtocol: %d, bNumEndpoints: %d\n",
                 interface->bInterfaceClass, interface->bInterfaceSubClass,
                 interface->bInterfaceProtocol, interface->bNumEndpoints);

            if (interface->bNumEndpoints == 2 &&
                    is_adb_interface(vid, pid, interface->bInterfaceClass,
                    interface->bInterfaceSubClass, interface->bInterfaceProtocol))  {

                DBGX("looking for bulk endpoints\n");
                    // looks like ADB...
                ep1 = (struct usb_endpoint_descriptor *)usb_descriptor_iter_next(&iter);
                ep2 = (struct usb_endpoint_descriptor *)usb_descriptor_iter_next(&iter);

                if (!ep1 || !ep2 ||
                    ep1->bDescriptorType != USB_DT_ENDPOINT ||
                    ep2->bDescriptorType != USB_DT_ENDPOINT) {
                    D("endpoints not found\n");
                    continue;
                }

                    // both endpoints should be bulk
                if (ep1->bmAttributes != USB_ENDPOINT_XFER_BULK ||
                    ep2->bmAttributes != USB_ENDPOINT_XFER_BULK) {
                    D("bulk endpoints not found\n");
                    continue;
                }

                    // we have a match.  now we just need to figure out which is in and which is out.
                if (ep1->bEndpointAddress & USB_ENDPOINT_DIR_MASK) {
                    ep_in = usb_endpoint_open(device, ep1);
                    ep_out = usb_endpoint_open(device, ep2);
                } else {
                    ep_in = usb_endpoint_open(device, ep2);
                    ep_out = usb_endpoint_open(device, ep1);
                }

                register_device(device, interface->bInterfaceNumber, ep_in, ep_out);
                // so we don't free it at the bottom
                device = NULL;
                break;
            }
        }
    } // end of while

    if (device)
        usb_device_close(device);
}

void usb_cleanup()
{
}

static int usb_bulk_write(usb_handle *h, const void *data, int len)
{
    struct usb_endpoint *ep = h->ep_out;
    int res;

    D("++ write ++\n");

    adb_mutex_lock(&h->lock);
    if(h->dead) {
        res = -1;
        goto fail;
    }
    res = usb_endpoint_queue(ep, (void *)data, len);
    if(res < 0) {
        goto fail;
    }

    res = pthread_cond_wait(&h->notify_out, &h->lock);
    if (!res)
        res = h->write_result;

fail:
    adb_mutex_unlock(&h->lock);
    D("-- write --\n");
    return res;
}

static int usb_bulk_read(usb_handle *h, void *data, int len)
{
    struct usb_endpoint *ep = h->ep_in;
    int res;

    adb_mutex_lock(&h->lock);
    if(h->dead) {
        res = -1;
        goto fail;
    }
    res = usb_endpoint_queue(ep, data, len);
    if (res < 0) {
        goto fail;
    }
    res = pthread_cond_wait(&h->notify_in, &h->lock);
    if (!res)
        res = h->read_result;

fail:
    adb_mutex_unlock(&h->lock);
    return res;
}

int usb_write(usb_handle *h, const void *_data, int len)
{
    unsigned char *data = (unsigned char*) _data;
    int n;
    int need_zero = 0;

    if(h->zero_mask) {
            /* if we need 0-markers and our transfer
            ** is an even multiple of the packet size,
            ** we make note of it
            */
        if(!(len & h->zero_mask)) {
            need_zero = 1;
        }
    }

    while(len > 0) {
        int xfer = (len > 4096) ? 4096 : len;

        n = usb_bulk_write(h, data, xfer);
        if(n != xfer) {
            D("ERROR: n = %d, errno = %d (%s)\n",
                n, errno, strerror(errno));
            return -1;
        }

        len -= xfer;
        data += xfer;
    }

    if(need_zero) {
        n = usb_bulk_write(h, _data, 0);
        return n;
    }

    return 0;
}

int usb_read(usb_handle *h, void *_data, int len)
{
    unsigned char *data = (unsigned char*) _data;
    int n;

    D("++ usb_read ++\n");
    while(len > 0) {
        int xfer = (len > 4096) ? 4096 : len;

        n = usb_bulk_read(h, data, xfer);
        if(n != xfer) {
            if(errno == ETIMEDOUT && h->device) {
                D("[ timeout ]\n");
                if(n > 0){
                    data += n;
                    len -= n;
                }
                continue;
            }
            D("ERROR: n = %d, errno = %d (%s)\n",
                n, errno, strerror(errno));
            return -1;
        }

        len -= xfer;
        data += xfer;
    }

    D("-- usb_read --\n");
    return 0;
}

void usb_kick(usb_handle *h)
{
    D("[ kicking %p (fd = %s) ]\n", h, usb_device_get_name(h->device));
    adb_mutex_lock(&h->lock);
    if(h->dead == 0) {
        h->dead = 1;

        if (usb_device_is_writeable(h->device)) {
            /* HACK ALERT!
            ** Sometimes we get stuck in ioctl(USBDEVFS_REAPURB).
            ** This is a workaround for that problem.
            */
            if (h->reaper_thread) {
                pthread_kill(h->reaper_thread, SIGALRM);
            }

            /* cancel any pending transactions
            ** these will quietly fail if the txns are not active,
            ** but this ensures that a reader blocked on REAPURB
            ** will get unblocked
            */
            usb_endpoint_cancel(h->ep_in);
            usb_endpoint_cancel(h->ep_out);
            adb_cond_broadcast(&h->notify_in);
            adb_cond_broadcast(&h->notify_out);
        } else {
            unregister_usb_transport(h);
        }
    }
    adb_mutex_unlock(&h->lock);
}

int usb_close(usb_handle *h)
{
    D("[ usb close ... ]\n");
    adb_mutex_lock(&usb_lock);
    h->next->prev = h->prev;
    h->prev->next = h->next;
    h->prev = 0;
    h->next = 0;

    usb_device_close(h->device);
    D("[ usb closed %p ]\n", h);
    adb_mutex_unlock(&usb_lock);

    free(h);
    return 0;
}

static void sigalrm_handler(int signo)
{
    // don't need to do anything here
}

void usb_init()
{
    struct sigaction    actions;

    if (usb_host_init(check_usb_device, kick_disconnected_device))
        fatal_errno("usb_host_init failed\n");

    memset(&actions, 0, sizeof(actions));
    sigemptyset(&actions.sa_mask);
    actions.sa_flags = 0;
    actions.sa_handler = sigalrm_handler;
    sigaction(SIGALRM,& actions, NULL);
}


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

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <dirent.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>

#include <linux/usbdevice_fs.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
#include <linux/usb/ch9.h>
#else
#include <linux/usb_ch9.h>
#endif
#include <asm/byteorder.h>

#include "sysdeps.h"

#define   TRACE_TAG  TRACE_USB
#include "adb.h"


/* usb scan debugging is waaaay too verbose */
#define DBGX(x...)

ADB_MUTEX_DEFINE( usb_lock );

struct usb_handle
{
    usb_handle *prev;
    usb_handle *next;

    char fname[64];
    int desc;
    unsigned char ep_in;
    unsigned char ep_out;

    unsigned zero_mask;
    unsigned writeable;

    struct usbdevfs_urb urb_in;
    struct usbdevfs_urb urb_out;

    int urb_in_busy;
    int urb_out_busy;
    int dead;

    adb_cond_t notify;
    adb_mutex_t lock;

    // for garbage collecting disconnected devices
    int mark;

    // ID of thread currently in REAPURB
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
    for(usb = handle_list.next; usb != &handle_list; usb = usb->next){
        if(!strcmp(usb->fname, dev_name)) {
            // set mark flag to indicate this device is still alive
            usb->mark = 1;
            adb_mutex_unlock(&usb_lock);
            return 1;
        }
    }
    adb_mutex_unlock(&usb_lock);
    return 0;
}

static void kick_disconnected_devices()
{
    usb_handle *usb;

    adb_mutex_lock(&usb_lock);
    // kick any devices in the device list that were not found in the device scan
    for(usb = handle_list.next; usb != &handle_list; usb = usb->next){
        if (usb->mark == 0) {
            usb_kick(usb);
        } else {
            usb->mark = 0;
        }
    }
    adb_mutex_unlock(&usb_lock);

}

static void register_device(const char *dev_name, unsigned char ep_in, unsigned char ep_out,
                            int ifc, int serial_index, unsigned zero_mask);

static inline int badname(const char *name)
{
    while(*name) {
        if(!isdigit(*name++)) return 1;
    }
    return 0;
}

static void find_usb_device(const char *base,
        void (*register_device_callback)
                (const char *, unsigned char, unsigned char, int, int, unsigned))
{
    char busname[32], devname[32];
    unsigned char local_ep_in, local_ep_out;
    DIR *busdir , *devdir ;
    struct dirent *de;
    int fd ;

    busdir = opendir(base);
    if(busdir == 0) return;

    while((de = readdir(busdir)) != 0) {
        if(badname(de->d_name)) continue;

        snprintf(busname, sizeof busname, "%s/%s", base, de->d_name);
        devdir = opendir(busname);
        if(devdir == 0) continue;

//        DBGX("[ scanning %s ]\n", busname);
        while((de = readdir(devdir))) {
            unsigned char devdesc[4096];
            unsigned char* bufptr = devdesc;
            unsigned char* bufend;
            struct usb_device_descriptor* device;
            struct usb_config_descriptor* config;
            struct usb_interface_descriptor* interface;
            struct usb_endpoint_descriptor *ep1, *ep2;
            unsigned zero_mask = 0;
            unsigned vid, pid;
            size_t desclength;

            if(badname(de->d_name)) continue;
            snprintf(devname, sizeof devname, "%s/%s", busname, de->d_name);

            if(known_device(devname)) {
                DBGX("skipping %s\n", devname);
                continue;
            }

//            DBGX("[ scanning %s ]\n", devname);
            if((fd = unix_open(devname, O_RDONLY)) < 0) {
                continue;
            }

            desclength = adb_read(fd, devdesc, sizeof(devdesc));
            bufend = bufptr + desclength;

                // should have device and configuration descriptors, and atleast two endpoints
            if (desclength < USB_DT_DEVICE_SIZE + USB_DT_CONFIG_SIZE) {
                D("desclength %d is too small\n", desclength);
                adb_close(fd);
                continue;
            }

            device = (struct usb_device_descriptor*)bufptr;
            bufptr += USB_DT_DEVICE_SIZE;

            if((device->bLength != USB_DT_DEVICE_SIZE) || (device->bDescriptorType != USB_DT_DEVICE)) {
                adb_close(fd);
                continue;
            }

            vid = device->idVendor;
            pid = device->idProduct;
            DBGX("[ %s is V:%04x P:%04x ]\n", devname, vid, pid);

                // should have config descriptor next
            config = (struct usb_config_descriptor *)bufptr;
            bufptr += USB_DT_CONFIG_SIZE;
            if (config->bLength != USB_DT_CONFIG_SIZE || config->bDescriptorType != USB_DT_CONFIG) {
                D("usb_config_descriptor not found\n");
                adb_close(fd);
                continue;
            }

                // loop through all the descriptors and look for the ADB interface
            while (bufptr < bufend) {
                unsigned char length = bufptr[0];
                unsigned char type = bufptr[1];

                if (type == USB_DT_INTERFACE) {
                    interface = (struct usb_interface_descriptor *)bufptr;
                    bufptr += length;

                    if (length != USB_DT_INTERFACE_SIZE) {
                        D("interface descriptor has wrong size\n");
                        break;
                    }

                    DBGX("bInterfaceClass: %d,  bInterfaceSubClass: %d,"
                         "bInterfaceProtocol: %d, bNumEndpoints: %d\n",
                         interface->bInterfaceClass, interface->bInterfaceSubClass,
                         interface->bInterfaceProtocol, interface->bNumEndpoints);

                    if (interface->bNumEndpoints == 2 &&
                            is_adb_interface(vid, pid, interface->bInterfaceClass,
                            interface->bInterfaceSubClass, interface->bInterfaceProtocol))  {

                        DBGX("looking for bulk endpoints\n");
                            // looks like ADB...
                        ep1 = (struct usb_endpoint_descriptor *)bufptr;
                        bufptr += USB_DT_ENDPOINT_SIZE;
                        ep2 = (struct usb_endpoint_descriptor *)bufptr;
                        bufptr += USB_DT_ENDPOINT_SIZE;

                        if (bufptr > devdesc + desclength ||
                            ep1->bLength != USB_DT_ENDPOINT_SIZE ||
                            ep1->bDescriptorType != USB_DT_ENDPOINT ||
                            ep2->bLength != USB_DT_ENDPOINT_SIZE ||
                            ep2->bDescriptorType != USB_DT_ENDPOINT) {
                            D("endpoints not found\n");
                            break;
                        }

                            // both endpoints should be bulk
                        if (ep1->bmAttributes != USB_ENDPOINT_XFER_BULK ||
                            ep2->bmAttributes != USB_ENDPOINT_XFER_BULK) {
                            D("bulk endpoints not found\n");
                            continue;
                        }
                            /* aproto 01 needs 0 termination */
                        if(interface->bInterfaceProtocol == 0x01) {
                            zero_mask = ep1->wMaxPacketSize - 1;
                        }

                            // we have a match.  now we just need to figure out which is in and which is out.
                        if (ep1->bEndpointAddress & USB_ENDPOINT_DIR_MASK) {
                            local_ep_in = ep1->bEndpointAddress;
                            local_ep_out = ep2->bEndpointAddress;
                        } else {
                            local_ep_in = ep2->bEndpointAddress;
                            local_ep_out = ep1->bEndpointAddress;
                        }

                        register_device_callback(devname, local_ep_in, local_ep_out,
                                interface->bInterfaceNumber, device->iSerialNumber, zero_mask);
                        break;
                    }
                } else {
                    bufptr += length;
                }
            } // end of while

            adb_close(fd);
        } // end of devdir while
        closedir(devdir);
    } //end of busdir while
    closedir(busdir);
}

void usb_cleanup()
{
}

static int usb_bulk_write(usb_handle *h, const void *data, int len)
{
    struct usbdevfs_urb *urb = &h->urb_out;
    int res;
    struct timeval tv;
    struct timespec ts;

    memset(urb, 0, sizeof(*urb));
    urb->type = USBDEVFS_URB_TYPE_BULK;
    urb->endpoint = h->ep_out;
    urb->status = -1;
    urb->buffer = (void*) data;
    urb->buffer_length = len;

    D("++ write ++\n");

    adb_mutex_lock(&h->lock);
    if(h->dead) {
        res = -1;
        goto fail;
    }
    do {
        res = ioctl(h->desc, USBDEVFS_SUBMITURB, urb);
    } while((res < 0) && (errno == EINTR));

    if(res < 0) {
        goto fail;
    }

    res = -1;
    h->urb_out_busy = 1;
    for(;;) {
        /* time out after five seconds */
        gettimeofday(&tv, NULL);
        ts.tv_sec = tv.tv_sec + 5;
        ts.tv_nsec = tv.tv_usec * 1000L;
        res = pthread_cond_timedwait(&h->notify, &h->lock, &ts);
        if(res < 0 || h->dead) {
            break;
        }
        if(h->urb_out_busy == 0) {
            if(urb->status == 0) {
                res = urb->actual_length;
            }
            break;
        }
    }
fail:
    adb_mutex_unlock(&h->lock);
    D("-- write --\n");
    return res;
}

static int usb_bulk_read(usb_handle *h, void *data, int len)
{
    struct usbdevfs_urb *urb = &h->urb_in;
    struct usbdevfs_urb *out = NULL;
    int res;

    memset(urb, 0, sizeof(*urb));
    urb->type = USBDEVFS_URB_TYPE_BULK;
    urb->endpoint = h->ep_in;
    urb->status = -1;
    urb->buffer = data;
    urb->buffer_length = len;


    adb_mutex_lock(&h->lock);
    if(h->dead) {
        res = -1;
        goto fail;
    }
    do {
        res = ioctl(h->desc, USBDEVFS_SUBMITURB, urb);
    } while((res < 0) && (errno == EINTR));

    if(res < 0) {
        goto fail;
    }

    h->urb_in_busy = 1;
    for(;;) {
        D("[ reap urb - wait ]\n");
        h->reaper_thread = pthread_self();
        adb_mutex_unlock(&h->lock);
        res = ioctl(h->desc, USBDEVFS_REAPURB, &out);
        int saved_errno = errno;
        adb_mutex_lock(&h->lock);
        h->reaper_thread = 0;
        if(h->dead) {
            res = -1;
            break;
        }
        if(res < 0) {
            if(saved_errno == EINTR) {
                continue;
            }
            D("[ reap urb - error ]\n");
            break;
        }
        D("[ urb @%p status = %d, actual = %d ]\n",
            out, out->status, out->actual_length);

        if(out == &h->urb_in) {
            D("[ reap urb - IN complete ]\n");
            h->urb_in_busy = 0;
            if(urb->status == 0) {
                res = urb->actual_length;
            } else {
                res = -1;
            }
            break;
        }
        if(out == &h->urb_out) {
            D("[ reap urb - OUT compelete ]\n");
            h->urb_out_busy = 0;
            adb_cond_broadcast(&h->notify);
        }
    }
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

    if(need_zero){
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

        D("[ usb read %d fd = %d], fname=%s\n", xfer, h->desc, h->fname);
        n = usb_bulk_read(h, data, xfer);
        D("[ usb read %d ] = %d, fname=%s\n", xfer, n, h->fname);
        if(n != xfer) {
            if((errno == ETIMEDOUT) && (h->desc != -1)) {
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
    D("[ kicking %p (fd = %d) ]\n", h, h->desc);
    adb_mutex_lock(&h->lock);
    if(h->dead == 0) {
        h->dead = 1;

        if (h->writeable) {
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
            ioctl(h->desc, USBDEVFS_DISCARDURB, &h->urb_in);
            ioctl(h->desc, USBDEVFS_DISCARDURB, &h->urb_out);
            h->urb_in.status = -ENODEV;
            h->urb_out.status = -ENODEV;
            h->urb_in_busy = 0;
            h->urb_out_busy = 0;
            adb_cond_broadcast(&h->notify);
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

    adb_close(h->desc);
    D("[ usb closed %p (fd = %d) ]\n", h, h->desc);
    adb_mutex_unlock(&usb_lock);

    free(h);
    return 0;
}

static void register_device(const char *dev_name,
                            unsigned char ep_in, unsigned char ep_out,
                            int interface, int serial_index, unsigned zero_mask)
{
    usb_handle* usb = 0;
    int n = 0;
    char serial[256];

        /* Since Linux will not reassign the device ID (and dev_name)
        ** as long as the device is open, we can add to the list here
        ** once we open it and remove from the list when we're finally
        ** closed and everything will work out fine.
        **
        ** If we have a usb_handle on the list 'o handles with a matching
        ** name, we have no further work to do.
        */
    adb_mutex_lock(&usb_lock);
    for(usb = handle_list.next; usb != &handle_list; usb = usb->next){
        if(!strcmp(usb->fname, dev_name)) {
            adb_mutex_unlock(&usb_lock);
            return;
        }
    }
    adb_mutex_unlock(&usb_lock);

    D("[ usb located new device %s (%d/%d/%d) ]\n",
        dev_name, ep_in, ep_out, interface);
    usb = calloc(1, sizeof(usb_handle));
    strcpy(usb->fname, dev_name);
    usb->ep_in = ep_in;
    usb->ep_out = ep_out;
    usb->zero_mask = zero_mask;
    usb->writeable = 1;

    adb_cond_init(&usb->notify, 0);
    adb_mutex_init(&usb->lock, 0);
    /* initialize mark to 1 so we don't get garbage collected after the device scan */
    usb->mark = 1;
    usb->reaper_thread = 0;

    usb->desc = unix_open(usb->fname, O_RDWR);
    if(usb->desc < 0) {
        /* if we fail, see if have read-only access */
        usb->desc = unix_open(usb->fname, O_RDONLY);
        if(usb->desc < 0) goto fail;
        usb->writeable = 0;
        D("[ usb open read-only %s fd = %d]\n", usb->fname, usb->desc);
    } else {
        D("[ usb open %s fd = %d]\n", usb->fname, usb->desc);
        n = ioctl(usb->desc, USBDEVFS_CLAIMINTERFACE, &interface);
        if(n != 0) goto fail;
    }

        /* read the device's serial number */
    serial[0] = 0;
    memset(serial, 0, sizeof(serial));
    if (serial_index) {
        struct usbdevfs_ctrltransfer  ctrl;
        __u16 buffer[128];
        __u16 languages[128];
        int i, result;
        int languageCount = 0;

        memset(languages, 0, sizeof(languages));
        memset(&ctrl, 0, sizeof(ctrl));

            // read list of supported languages
        ctrl.bRequestType = USB_DIR_IN|USB_TYPE_STANDARD|USB_RECIP_DEVICE;
        ctrl.bRequest = USB_REQ_GET_DESCRIPTOR;
        ctrl.wValue = (USB_DT_STRING << 8) | 0;
        ctrl.wIndex = 0;
        ctrl.wLength = sizeof(languages);
        ctrl.data = languages;

        result = ioctl(usb->desc, USBDEVFS_CONTROL, &ctrl);
        if (result > 0)
            languageCount = (result - 2) / 2;

        for (i = 1; i <= languageCount; i++) {
            memset(buffer, 0, sizeof(buffer));
            memset(&ctrl, 0, sizeof(ctrl));

            ctrl.bRequestType = USB_DIR_IN|USB_TYPE_STANDARD|USB_RECIP_DEVICE;
            ctrl.bRequest = USB_REQ_GET_DESCRIPTOR;
            ctrl.wValue = (USB_DT_STRING << 8) | serial_index;
            ctrl.wIndex = __le16_to_cpu(languages[i]);
            ctrl.wLength = sizeof(buffer);
            ctrl.data = buffer;

            result = ioctl(usb->desc, USBDEVFS_CONTROL, &ctrl);
            if (result > 0) {
                int i;
                // skip first word, and copy the rest to the serial string, changing shorts to bytes.
                result /= 2;
                for (i = 1; i < result; i++)
                    serial[i - 1] = __le16_to_cpu(buffer[i]);
                serial[i - 1] = 0;
                break;
            }
        }
    }

        /* add to the end of the active handles */
    adb_mutex_lock(&usb_lock);
    usb->next = &handle_list;
    usb->prev = handle_list.prev;
    usb->prev->next = usb;
    usb->next->prev = usb;
    adb_mutex_unlock(&usb_lock);

    register_usb_transport(usb, serial, usb->writeable);
    return;

fail:
    D("[ usb open %s error=%d, err_str = %s]\n",
        usb->fname,  errno, strerror(errno));
    if(usb->desc >= 0) {
        adb_close(usb->desc);
    }
    free(usb);
}

void* device_poll_thread(void* unused)
{
    D("Created device thread\n");
    for(;;) {
            /* XXX use inotify */
        find_usb_device("/dev/bus/usb", register_device);
        kick_disconnected_devices();
        sleep(1);
    }
    return NULL;
}

static void sigalrm_handler(int signo)
{
    // don't need to do anything here
}

void usb_init()
{
    adb_thread_t tid;
    struct sigaction    actions;

    memset(&actions, 0, sizeof(actions));
    sigemptyset(&actions.sa_mask);
    actions.sa_flags = 0;
    actions.sa_handler = sigalrm_handler;
    sigaction(SIGALRM,& actions, NULL);

    if(adb_thread_create(&tid, device_poll_thread, NULL)){
        fatal_errno("cannot create input thread");
    }
}

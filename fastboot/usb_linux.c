/*
 * Copyright (C) 2008 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the 
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED 
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <dirent.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <ctype.h>

#include <linux/usbdevice_fs.h>
#include <linux/usbdevice_fs.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
#include <linux/usb/ch9.h>
#else
#include <linux/usb_ch9.h>
#endif
#include <asm/byteorder.h>

#include "usb.h"

#define MAX_RETRIES 5

#ifdef TRACE_USB
#define DBG1(x...) fprintf(stderr, x)
#define DBG(x...) fprintf(stderr, x)
#else
#define DBG(x...)
#define DBG1(x...)
#endif

struct usb_handle 
{
    char fname[64];
    int desc;
    unsigned char ep_in;
    unsigned char ep_out;
};

static inline int badname(const char *name)
{
    while(*name) {
        if(!isdigit(*name++)) return 1;
    }
    return 0;
}

static int check(void *_desc, int len, unsigned type, int size)
{
    unsigned char *desc = _desc;
    
    if(len < size) return -1;
    if(desc[0] < size) return -1;
    if(desc[0] > len) return -1;
    if(desc[1] != type) return -1;
    
    return 0;
}

static int filter_usb_device(int fd, char *ptr, int len, int writable,
                             ifc_match_func callback,
                             int *ept_in_id, int *ept_out_id, int *ifc_id)
{
    struct usb_device_descriptor *dev;
    struct usb_config_descriptor *cfg;
    struct usb_interface_descriptor *ifc;
    struct usb_endpoint_descriptor *ept;
    struct usb_ifc_info info;
    
    int in, out;
    unsigned i;
    unsigned e;
    
    if(check(ptr, len, USB_DT_DEVICE, USB_DT_DEVICE_SIZE))
        return -1;
    dev = (void*) ptr;
    len -= dev->bLength;
    ptr += dev->bLength;
    
    if(check(ptr, len, USB_DT_CONFIG, USB_DT_CONFIG_SIZE))
        return -1;
    cfg = (void*) ptr;
    len -= cfg->bLength;
    ptr += cfg->bLength;
    
    info.dev_vendor = dev->idVendor;
    info.dev_product = dev->idProduct;
    info.dev_class = dev->bDeviceClass;
    info.dev_subclass = dev->bDeviceSubClass;
    info.dev_protocol = dev->bDeviceProtocol;
    info.writable = writable;
    
    // read device serial number (if there is one)
    info.serial_number[0] = 0;
    if (dev->iSerialNumber) {
        struct usbdevfs_ctrltransfer  ctrl;
        __u16 buffer[128];
        int result;

        memset(buffer, 0, sizeof(buffer));

        ctrl.bRequestType = USB_DIR_IN|USB_TYPE_STANDARD|USB_RECIP_DEVICE;
        ctrl.bRequest = USB_REQ_GET_DESCRIPTOR;
        ctrl.wValue = (USB_DT_STRING << 8) | dev->iSerialNumber;
        ctrl.wIndex = 0;
        ctrl.wLength = sizeof(buffer);
        ctrl.data = buffer;

        result = ioctl(fd, USBDEVFS_CONTROL, &ctrl);
        if (result > 0) {
            int i;
            // skip first word, and copy the rest to the serial string, changing shorts to bytes.
            result /= 2;
            for (i = 1; i < result; i++)
                info.serial_number[i - 1] = buffer[i];
            info.serial_number[i - 1] = 0;
        }
    }

    for(i = 0; i < cfg->bNumInterfaces; i++) {
        if(check(ptr, len, USB_DT_INTERFACE, USB_DT_INTERFACE_SIZE))
            return -1;
        ifc = (void*) ptr;
        len -= ifc->bLength;
        ptr += ifc->bLength;
        
        in = -1;
        out = -1;
        info.ifc_class = ifc->bInterfaceClass;
        info.ifc_subclass = ifc->bInterfaceSubClass;
        info.ifc_protocol = ifc->bInterfaceProtocol;
        
        for(e = 0; e < ifc->bNumEndpoints; e++) {
            if(check(ptr, len, USB_DT_ENDPOINT, USB_DT_ENDPOINT_SIZE))
                return -1;
            ept = (void*) ptr;
            len -= ept->bLength;
            ptr += ept->bLength;
    
            if((ept->bmAttributes & 0x03) != 0x02)
                continue;
            
            if(ept->bEndpointAddress & 0x80) {
                in = ept->bEndpointAddress;
            } else {
                out = ept->bEndpointAddress;
            }
        }

        info.has_bulk_in = (in != -1);
        info.has_bulk_out = (out != -1);
        
        if(callback(&info) == 0) {
            *ept_in_id = in;
            *ept_out_id = out;
            *ifc_id = ifc->bInterfaceNumber;
            return 0;
        }
    }

    return -1;
}

static usb_handle *find_usb_device(const char *base, ifc_match_func callback)
{
    usb_handle *usb = 0;
    char busname[64], devname[64];
    char desc[1024];
    int n, in, out, ifc;
    
    DIR *busdir, *devdir;
    struct dirent *de;
    int fd;
    int writable;
    
    busdir = opendir(base);
    if(busdir == 0) return 0;

    while((de = readdir(busdir)) && (usb == 0)) {
        if(badname(de->d_name)) continue;
        
        sprintf(busname, "%s/%s", base, de->d_name);
        devdir = opendir(busname);
        if(devdir == 0) continue;
        
//        DBG("[ scanning %s ]\n", busname);
        while((de = readdir(devdir)) && (usb == 0)) {
            
            if(badname(de->d_name)) continue;
            sprintf(devname, "%s/%s", busname, de->d_name);

//            DBG("[ scanning %s ]\n", devname);
            writable = 1;
            if((fd = open(devname, O_RDWR)) < 0) {
                // Check if we have read-only access, so we can give a helpful
                // diagnostic like "adb devices" does.
                writable = 0;
                if((fd = open(devname, O_RDONLY)) < 0) {
                    continue;
                }
            }

            n = read(fd, desc, sizeof(desc));
            
            if(filter_usb_device(fd, desc, n, writable, callback,
                                 &in, &out, &ifc) == 0) {
                usb = calloc(1, sizeof(usb_handle));
                strcpy(usb->fname, devname);
                usb->ep_in = in;
                usb->ep_out = out;
                usb->desc = fd;

                n = ioctl(fd, USBDEVFS_CLAIMINTERFACE, &ifc);
                if(n != 0) {
                    close(fd);
                    free(usb);
                    usb = 0;
                    continue;
                }
            } else {
                close(fd);
            }
        }
        closedir(devdir);
    }
    closedir(busdir);

    return usb;
}

int usb_write(usb_handle *h, const void *_data, int len)
{
    unsigned char *data = (unsigned char*) _data;
    unsigned count = 0;
    struct usbdevfs_bulktransfer bulk;
    int n;

    if(h->ep_out == 0) {
        return -1;
    }
    
    if(len == 0) {
        bulk.ep = h->ep_out;
        bulk.len = 0;
        bulk.data = data;
        bulk.timeout = 0;
        
        n = ioctl(h->desc, USBDEVFS_BULK, &bulk);
        if(n != 0) {
            fprintf(stderr,"ERROR: n = %d, errno = %d (%s)\n",
                    n, errno, strerror(errno));
            return -1;
        }
        return 0;
    }
    
    while(len > 0) {
        int xfer;
        xfer = (len > 4096) ? 4096 : len;
        
        bulk.ep = h->ep_out;
        bulk.len = xfer;
        bulk.data = data;
        bulk.timeout = 0;
        
        n = ioctl(h->desc, USBDEVFS_BULK, &bulk);
        if(n != xfer) {
            DBG("ERROR: n = %d, errno = %d (%s)\n",
                n, errno, strerror(errno));
            return -1;
        }

        count += xfer;
        len -= xfer;
        data += xfer;
    }

    return count;
}

int usb_read(usb_handle *h, void *_data, int len)
{
    unsigned char *data = (unsigned char*) _data;
    unsigned count = 0;
    struct usbdevfs_bulktransfer bulk;
    int n, retry;

    if(h->ep_in == 0) {
        return -1;
    }
    
    while(len > 0) {
        int xfer = (len > 4096) ? 4096 : len;
        
        bulk.ep = h->ep_in;
        bulk.len = xfer;
        bulk.data = data;
        bulk.timeout = 0;
        retry = 0;

        do{
           DBG("[ usb read %d fd = %d], fname=%s\n", xfer, h->desc, h->fname);
           n = ioctl(h->desc, USBDEVFS_BULK, &bulk);
           DBG("[ usb read %d ] = %d, fname=%s, Retry %d \n", xfer, n, h->fname, retry);

           if( n < 0 ) {
            DBG1("ERROR: n = %d, errno = %d (%s)\n",n, errno, strerror(errno));
            if ( ++retry > MAX_RETRIES ) return -1;
            sleep( 1 );
           }
        }
        while( n < 0 );

        count += n;
        len -= n;
        data += n;
        
        if(n < xfer) {
            break;
        }
    }
    
    return count;
}

void usb_kick(usb_handle *h)
{
    int fd;

    fd = h->desc;
    h->desc = -1;
    if(fd >= 0) {
        close(fd);
        DBG("[ usb closed %d ]\n", fd);
    }
}

int usb_close(usb_handle *h)
{
    int fd;
    
    fd = h->desc;
    h->desc = -1;
    if(fd >= 0) {
        close(fd);
        DBG("[ usb closed %d ]\n", fd);
    }

    return 0;
}

usb_handle *usb_open(ifc_match_func callback)
{
    return find_usb_device("/dev/bus/usb", callback);
}

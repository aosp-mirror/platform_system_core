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

#define _GNU_SOURCE
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
#include <linux/version.h>
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
#include <linux/usb/ch9.h>
#else
#include <linux/usb_ch9.h>
#endif
#include <asm/byteorder.h>

#include <cutils/fdevent.h>
#include "adb.h"


#define TRACE_USB 0

#if TRACE_USB
#define DBG1(x...) fprintf(stderr, x)
#define DBG(x...) fprintf(stderr, x)
#else
#define DBG(x...)
#define DBG1(x...)
#endif

struct usb_handle
{
    struct usb_handle *next;
    char fname[32];
    int desc;
    unsigned char ep_in;
    unsigned char ep_out;
    unsigned int interface;
};

static struct usb_handle *g_first_usb_device;
static struct usb_handle *g_last_usb_device;

static void new_device(char *dev_name, unsigned char ep_in, unsigned char ep_out, unsigned int interface)
{
    struct usb_handle* usb;

    DBG("New device being added %s \n", dev_name);

    usb = (struct usb_handle *)calloc(1, sizeof(struct usb_handle));
    strcpy(usb->fname, dev_name);
    usb->ep_in = ep_in;
    usb->ep_out = ep_out;
    usb->interface = interface;
    usb->next = NULL;
    if(g_last_usb_device)
        g_last_usb_device->next = usb;
    else
        g_first_usb_device = usb;
    g_last_usb_device = usb;
}


static inline int badname(const char *name)
{
    if(!isdigit(name[0])) return 1;
    if(!isdigit(name[1])) return 1;
    if(!isdigit(name[2])) return 1;
    if(name[3] != 0) return 1;
    return 0;
}

static int find_usb_devices(const char *base, unsigned vendor, unsigned product1, unsigned product2,
                            unsigned ifclass, unsigned ifsubclass,
                            unsigned ifprotocol, unsigned numendpoints)
{
    char busname[32], devname[32];
    unsigned char local_ep_in, local_ep_out;
    DIR *busdir , *devdir ;
    struct dirent *de;
    int fd ;
    int ret_val = -1;
    int found_device = 0;

    busdir = opendir(base);
    if(busdir == 0) return 0;

    while((de = readdir(busdir)) != 0) {
        if(badname(de->d_name)) continue;

        snprintf(busname, sizeof busname, "%s/%s", base, de->d_name);
        devdir = opendir(busname);
        if(devdir == 0) continue;

        DBG("[ scanning %s ]\n", busname);
        while((de = readdir(devdir))) {
            if(badname(de->d_name)) continue;
            snprintf(devname, sizeof devname, "%s/%s", busname, de->d_name);

            DBG("[ scanning %s ]\n", devname);
            fd = open(devname, O_RDWR);
            if(fd < 0) {
                continue;
            } else {
                unsigned char devdesc[256];
                unsigned char* bufptr = devdesc;
                struct usb_device_descriptor* device;
                struct usb_config_descriptor* config;
                struct usb_interface_descriptor* interface;
                struct usb_endpoint_descriptor *ep1, *ep2;
                unsigned vid, pid;
                int i, interfaces;

                size_t desclength = read(fd, devdesc, sizeof(devdesc));

                // should have device and configuration descriptors, and atleast two endpoints
                if (desclength < USB_DT_DEVICE_SIZE + USB_DT_CONFIG_SIZE) {
                    DBG("desclength %d is too small\n", desclength);
                    close(fd);
                    continue;
                }

                device = (struct usb_device_descriptor*)bufptr;
                bufptr += USB_DT_DEVICE_SIZE;
                if(device->bLength == USB_DT_DEVICE_SIZE && device->bDescriptorType == USB_DT_DEVICE) {
                    vid = __le16_to_cpu(device->idVendor);
                    pid = __le16_to_cpu(device->idProduct);
                    pid = devdesc[10] | (devdesc[11] << 8);
                    DBG("[ %s is V:%04x P:%04x ]\n", devname, vid, pid);
                    if((vendor == vid) && (product1 == pid || product2 == pid)){

                       // should have config descriptor next
                       config = (struct usb_config_descriptor *)bufptr;
                       bufptr += USB_DT_CONFIG_SIZE;
                       if (config->bLength != USB_DT_CONFIG_SIZE || config->bDescriptorType != USB_DT_CONFIG) {
                            DBG("usb_config_descriptor not found\n");
                            close(fd);
                            continue;
                           }

                           // loop through all the interfaces and look for the ADB interface
                           interfaces = config->bNumInterfaces;
                           for (i = 0; i < interfaces; i++) {
                              if (bufptr + USB_DT_ENDPOINT_SIZE > devdesc + desclength)
                                 break;

                              interface = (struct usb_interface_descriptor *)bufptr;
                              bufptr += USB_DT_INTERFACE_SIZE;
                              if (interface->bLength != USB_DT_INTERFACE_SIZE ||
                              interface->bDescriptorType != USB_DT_INTERFACE) {
                              DBG("usb_interface_descriptor not found\n");
                                  break;
                              }

                          DBG("bInterfaceClass: %d,  bInterfaceSubClass: %d,\
                              bInterfaceProtocol: %d, bNumEndpoints: %d\n",
                              interface->bInterfaceClass, interface->bInterfaceSubClass,
                              interface->bInterfaceProtocol, interface->bNumEndpoints);
                          // Sooner bootloader has zero for bInterfaceClass, while adb has USB_CLASS_CDC_DATA
                              if (interface->bInterfaceClass == ifclass &&
                                   interface->bInterfaceSubClass == ifsubclass &&
                                   interface->bInterfaceProtocol == ifprotocol &&
                                   interface->bNumEndpoints == numendpoints) {

                                   DBG("looking for bulk endpoints\n");
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
                                       DBG("endpoints not found\n");
                                       break;
                                  }

                                  // both endpoints should be bulk
                                  if (ep1->bmAttributes != USB_ENDPOINT_XFER_BULK ||
                                     ep2->bmAttributes != USB_ENDPOINT_XFER_BULK) {
                                      DBG("bulk endpoints not found\n");
                                      continue;
                                  }

                                  // we have a match.  now we just need to figure out which is in and which is out.
                                  if (ep1->bEndpointAddress & USB_ENDPOINT_DIR_MASK) {
                                      local_ep_in = ep1->bEndpointAddress;
                                      local_ep_out = ep2->bEndpointAddress;
                                  } else {
                                      local_ep_in = ep2->bEndpointAddress;
                                      local_ep_out = ep1->bEndpointAddress;
                                  }

                                  new_device(devname, local_ep_in, local_ep_out, i);
                                  found_device = 1;
                                  close(fd);
                              } else {
                                  // skip to next interface
                                  bufptr += (interface->bNumEndpoints * USB_DT_ENDPOINT_SIZE);
                              }
                          } // end of for
                    } //end of productid if
                }
                close(fd);
            } // end of if
        } // end of devdir while
        closedir(devdir);
    } //end of busdir while
    closedir(busdir);

    return found_device;
}


static void find_devices(unsigned vendor, unsigned product1, unsigned product2)
{
    // don't scan /proc/bus/usb if we find something in /dev/bus/usb, to avoid duplication of devices.
    if (!find_usb_devices("/dev/bus/usb", vendor, product1, product2, USB_CLASS_VENDOR_SPEC, 1, 0, 2)) {
        find_usb_devices("/proc/bus/usb", vendor, product1, product2, USB_CLASS_VENDOR_SPEC, 1, 0, 2);
    }
}

void usb_open_device(struct usb_handle *h)
{
    int n = 0;

    h->desc = open(h->fname, O_RDWR);
    //DBG("[ usb open %s fd = %d]\n", h->fname, h->desc);
    n = ioctl(h->desc, USBDEVFS_CLAIMINTERFACE, &h->interface);
    if(n != 0) goto fail;
//    t->usb_is_open = 1;
    return;


fail:
    DBG("[ usb open %s error=%d, err_str = %s]\n",
                h->fname,  errno, strerror(errno));
    if(h->desc >= 0) {
        close(h->desc);
        h->desc = -1;
    }
//    t->usb_is_open = 0;
}

int usb_write(struct usb_handle *h, const void *_data, int len)
{
    unsigned char *data = (unsigned char*) _data;
    struct usbdevfs_bulktransfer bulk;
    int n;

    while(len >= 0) {
        int xfer = (len > 4096) ? 4096 : len;

        bulk.ep = h->ep_out;
        bulk.len = xfer;
        bulk.data = data;
        bulk.timeout = 500 + xfer * 8;

        bulk.timeout *= 10;

        n = ioctl(h->desc, USBDEVFS_BULK, &bulk);
        if(n != xfer) {
            DBG("ERROR: n = %d, errno = %d (%s)\n",
                n, errno, strerror(errno));
            return -1;
        }
        if(len == 0)
            break;

        len -= xfer;
        data += xfer;
        if(len == 0)
            break;
    }

    return 0;
}

int usb_read(struct usb_handle *h, void *_data, int len)
{
    unsigned char *data_start = (unsigned char*) _data;
    unsigned char *data = (unsigned char*) _data;
    struct usbdevfs_bulktransfer bulk;
    int n;

    while(len > 0) {
        int xfer = (len > 4096) ? 4096 : len;

        bulk.ep = h->ep_in;
        bulk.len = xfer;
        bulk.data = data;

            // adjust timeout based on the data we're transferring,
            // otherwise the timeout interrupts us partway through
            // and we get out of sync...
        bulk.timeout = 500 + xfer * 8;

        bulk.timeout = 500 + xfer / 128;

//        bulk.timeout *= 10;
        DBG1("[ usb read %d fd = %d], fname=%s\n", xfer, h->desc, h->fname);
        n = ioctl(h->desc, USBDEVFS_BULK, &bulk);
        DBG1("[ usb read %d ] = %d, fname=%s\n", xfer, n, h->fname);
        if(n < 0) {
            if((errno == ETIMEDOUT) && (h->desc != -1)) {
                DBG("[ timeout ]\n");
                if(n > 0){
                    data += n;
                    len -= n;
                }
                continue;
            }
            DBG1("ERROR: n = %d, errno = %d (%s)\n",
                n, errno, strerror(errno));
            return -1;
        }

        len -= n;
        data += n;
        if(n != xfer)
            break;
    }

    return data - data_start;
}

void usb_kick(struct usb_handle *h)
{
    close(h->desc);
    h->desc = -1;
}

int usb_close(struct usb_handle *h)
{
    close(h->desc);
    h->desc = -1;
    return 0;
}

void list_devices()
{
    int i = 0;
    struct usb_handle *h = g_first_usb_device;
    while(h) {
        printf("%d: %s\n", i, h->fname);
        i++;
        h = h->next;
    }
}

int main(int argc, char **argv)
{
    char buffer[4096/*-64*/];
    int len;
    int c;
    char *arg;
    int device_index = 0;
    struct usb_handle *h;
    int i;

    find_devices(VENDOR_ID_GOOGLE, PRODUCT_ID_SOONER, PRODUCT_ID_SOONER_COMP);
    while(1) {
        c = getopt(argc, argv, "d:l");
        if (c == EOF)
            break;
        switch(c) {
            case 'd':
                device_index = strtol(optarg, NULL, 0);
                break;
            case 'l':
                list_devices();
                return 0;
            case '?':
                fprintf(stderr, "%s: invalid option -%c\n",
                        argv[0], optopt);
                return 1;
        }
    }

    argc -= optind - 1;
    argv += optind - 1;

    h = g_first_usb_device;
    i = device_index;
    while(i-- > 0 && h) {
        h = h->next;
    }
    if(h == NULL) {
        fprintf(stderr, "no device %d\n", device_index);
        return 1;
    }

    usb_open_device(h);
    if(g_first_usb_device->desc < 0) {
        fprintf(stderr, "could not open device (%s), %s\n", h->fname, strerror(errno));
        return 1;
    }
    len = 0;
    if(argc == 1) {
        char *line = NULL;
        size_t line_size = 0;
        while((len = getline(&line, &line_size, stdin)) >= 0) {
            //if(len > 0 && line[len - 1] == '\n')
            //  len--;
            usb_write(h, line, len);
            while(1) {
                len = usb_read(h, buffer, sizeof(buffer));
                if(len < 0)
                    break;
                write(STDOUT_FILENO, buffer, len);
                if(len < (int)sizeof(buffer))
                    break;
            }
        }
        return 0;
    }
    while(argc > 1) {
        argc--;
        argv++;
        arg = *argv;
        while(arg) {
            if(*arg)
                buffer[len++] = *arg++;
            else {
                arg = NULL;
                if(argc > 1)
                    buffer[len++] = ' ';
                else
                    break;
            }
            if(len == sizeof(buffer)) {
                usb_write(h, buffer, len);
                len = 0;
            }
        }
    }
    usb_write(h, buffer, len);
    while(1) {
        len = usb_read(h, buffer, sizeof(buffer));
        if(len < 0)
            break;
        write(STDOUT_FILENO, buffer, len);
        if(len < (int)sizeof(buffer))
            break;
    }
    return 0;
}

/* 
 * Copyright (C) 2009 bsdroid project
 *               Alexey Tarasov <tarasov@dodologics.com>
 *   
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

#include <sys/endian.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <err.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>
#include <libusb.h>
#include "sysdeps.h"

#define   TRACE_TAG  TRACE_USB
#include "adb.h"

static adb_mutex_t usb_lock = ADB_MUTEX_INITIALIZER;
static libusb_context *ctx = NULL;

struct usb_handle
{
    usb_handle            *prev;
    usb_handle            *next;

    libusb_device         *dev;
    libusb_device_handle  *devh;
    int                   interface;
    uint8_t               dev_bus;
    uint8_t               dev_addr;
	
    int                   zero_mask;
    unsigned char         end_point_address[2];
    char                  serial[128];
    
    adb_cond_t            notify;
    adb_mutex_t           lock;
};

static struct usb_handle handle_list = {
        .prev = &handle_list,
        .next = &handle_list,
};

void
usb_cleanup()
{
	libusb_exit(ctx);
}

void
report_bulk_libusb_error(int r)
{
    switch (r) {
    case LIBUSB_ERROR_TIMEOUT:
        D("Transfer timeout\n");
        break;

    case LIBUSB_ERROR_PIPE:
        D("Control request is not supported\n");
        break;

    case LIBUSB_ERROR_OVERFLOW:
        D("Device offered more data\n");
        break;

    case LIBUSB_ERROR_NO_DEVICE :
        D("Device was disconnected\n");
        break;

    default:
        D("Error %d during transfer\n", r);
        break;
    };
}

static int
usb_bulk_write(usb_handle *uh, const void *data, int len)
{
    int r = 0;
    int transferred = 0;

    r = libusb_bulk_transfer(uh->devh, uh->end_point_address[1], (void *)data, len,
                             &transferred, 0);
   
    if (r != 0) {
        D("usb_bulk_write(): ");
        report_bulk_libusb_error(r);
        return r;
    }
   
    return (transferred);
}

static int
usb_bulk_read(usb_handle *uh, void *data, int len)
{
    int r = 0;
    int transferred = 0;

    r = libusb_bulk_transfer(uh->devh, uh->end_point_address[0], data, len,
                             &transferred, 0);

    if (r != 0) {
        D("usb_bulk_read(): ");
        report_bulk_libusb_error(r);
        return r;
    }
   
    return (transferred);
}

int
usb_write(struct usb_handle *uh, const void *_data, int len)
{
    unsigned char *data = (unsigned char*) _data;
    int n;
    int need_zero = 0;

    if (uh->zero_mask == 1) {
        if (!(len & uh->zero_mask)) {
            need_zero = 1;
        }
    }

    D("usb_write(): %p:%d -> transport %p\n", _data, len, uh);
    
    while (len > 0) {
        int xfer = (len > 4096) ? 4096 : len;

        n = usb_bulk_write(uh, data, xfer);
        
        if (n != xfer) {
            D("usb_write(): failed for transport %p (%d bytes left)\n", uh, len);
            return -1;
        }

        len -= xfer;
        data += xfer;
    }

    if (need_zero){
        n = usb_bulk_write(uh, _data, 0);
        
        if (n < 0) {
            D("usb_write(): failed to finish operation for transport %p\n", uh);
        }
        return n;
    }

    return 0;
}

int
usb_read(struct usb_handle *uh, void *_data, int len)
{
    unsigned char *data = (unsigned char*) _data;
    int n;

    D("usb_read(): %p:%d <- transport %p\n", _data, len, uh);
    
    while (len > 0) {
        int xfer = (len > 4096) ? 4096 : len;

        n = usb_bulk_read(uh, data, xfer);
        
        if (n != xfer) {
            if (n > 0) {
                data += n;
                len -= n;
                continue;
            }
            
            D("usb_read(): failed for transport %p (%d bytes left)\n", uh, len);
            return -1;
        }

        len -= xfer;
        data += xfer;
    }

    return 0;
 }

int
usb_close(struct usb_handle *h)
{
    D("usb_close(): closing transport %p\n", h);
    adb_mutex_lock(&usb_lock);
    
    h->next->prev = h->prev;
    h->prev->next = h->next;
    h->prev = NULL;
    h->next = NULL;

    libusb_release_interface(h->devh, h->interface);
    libusb_close(h->devh);
    libusb_unref_device(h->dev);
    
    adb_mutex_unlock(&usb_lock);

    free(h);

    return (0);
}

void usb_kick(struct usb_handle *h)
{
    D("usb_cick(): kicking transport %p\n", h);
    
    adb_mutex_lock(&h->lock);
    unregister_usb_transport(h);
    adb_mutex_unlock(&h->lock);
    
    h->next->prev = h->prev;
    h->prev->next = h->next;
    h->prev = NULL;
    h->next = NULL;

    libusb_release_interface(h->devh, h->interface);
    libusb_close(h->devh);
    libusb_unref_device(h->dev);
    free(h);
}

int
check_usb_interface(libusb_interface *interface,
                    libusb_device_descriptor *desc,
                    struct usb_handle *uh)
{    
    int e;
    
    if (interface->num_altsetting == 0) {
        D("check_usb_interface(): No interface settings\n");
        return -1;
    }
    
    libusb_interface_descriptor *idesc = &interface->altsetting[0];
    
    if (idesc->bNumEndpoints != 2) {
        D("check_usb_interface(): Interface have not 2 endpoints, ignoring\n");
        return -1;
    }

    for (e = 0; e < idesc->bNumEndpoints; e++) {
        libusb_endpoint_descriptor *edesc = &idesc->endpoint[e];
        
        if (edesc->bmAttributes != LIBUSB_TRANSFER_TYPE_BULK) {
            D("check_usb_interface(): Endpoint (%u) is not bulk (%u), ignoring\n",
                    edesc->bmAttributes, LIBUSB_TRANSFER_TYPE_BULK);
            return -1;
        }
        
        if (edesc->bEndpointAddress & LIBUSB_ENDPOINT_IN)
            uh->end_point_address[0] = edesc->bEndpointAddress;
        else
            uh->end_point_address[1] = edesc->bEndpointAddress;
        
            /* aproto 01 needs 0 termination */
        if (idesc->bInterfaceProtocol == 0x01) {
            uh->zero_mask = edesc->wMaxPacketSize - 1;
            D("check_usb_interface(): Forced Android interface protocol v.1\n");
        }
    }

    D("check_usb_interface(): Device: %04x:%04x "
      "iclass: %x, isclass: %x, iproto: %x ep: %x/%x-> ",
        desc->idVendor, desc->idProduct, idesc->bInterfaceClass,
	idesc->bInterfaceSubClass, idesc->bInterfaceProtocol,
	uh->end_point_address[0], uh->end_point_address[1]);
    
    if (!is_adb_interface(desc->idVendor, desc->idProduct,
            idesc->bInterfaceClass, idesc->bInterfaceSubClass,
            idesc->bInterfaceProtocol))
    {
        D("not matches\n");
        return -1;
    }

    D("matches\n");
    return 1;
}

int
check_usb_interfaces(libusb_config_descriptor *config,
                     libusb_device_descriptor *desc, struct usb_handle *uh)
{  
    int i;
    
    for (i = 0; i < config->bNumInterfaces; ++i) {
        if (check_usb_interface(&config->interface[i], desc, uh) != -1) {
            /* found some interface and saved information about it */
            D("check_usb_interfaces(): Interface %d of %04x:%04x "
              "matches Android device\n", i, desc->idVendor,
	      desc->idProduct);
            
            return  i;
        }
    }
    
    return -1;
}

int
register_device(struct usb_handle *uh, const char *serial)
{
    D("register_device(): Registering %p [%s] as USB transport\n",
       uh, serial);

    struct usb_handle *usb= NULL;

    usb = calloc(1, sizeof(struct usb_handle));
    memcpy(usb, uh, sizeof(struct usb_handle));
    strcpy(usb->serial, uh->serial);

    adb_cond_init(&usb->notify, 0);
    adb_mutex_init(&usb->lock, 0);

    adb_mutex_lock(&usb_lock);
    
    usb->next = &handle_list;
    usb->prev = handle_list.prev;
    usb->prev->next = usb;
    usb->next->prev = usb;

    adb_mutex_unlock(&usb_lock);

    register_usb_transport(usb, serial, 1); 

    return (1);
}

int
already_registered(usb_handle *uh)
{
    struct usb_handle *usb= NULL;
    int exists = 0;
    
    adb_mutex_lock(&usb_lock);

    for (usb = handle_list.next; usb != &handle_list; usb = usb->next) {
        if ((usb->dev_bus == uh->dev_bus) &&
            (usb->dev_addr == uh->dev_addr))
        {
            exists = 1;
            break;
        }
    }

    adb_mutex_unlock(&usb_lock);

    return exists;
}

void
check_device(libusb_device *dev) 
{
    struct usb_handle uh;
    int i = 0;
    int found = -1;
    char serial[256] = {0};

    libusb_device_descriptor desc;
    libusb_config_descriptor *config = NULL;
    
    int r = libusb_get_device_descriptor(dev, &desc);

    if (r != LIBUSB_SUCCESS) {
        D("check_device(): Failed to get device descriptor\n");
        return;
    }
    
    if ((desc.idVendor == 0) && (desc.idProduct == 0))
        return;
    
    D("check_device(): Probing usb device %04x:%04x\n",
        desc.idVendor, desc.idProduct);
    
    if (!is_adb_interface (desc.idVendor, desc.idProduct,
                           ADB_CLASS, ADB_SUBCLASS, ADB_PROTOCOL))
    {
        D("check_device(): Ignored due unknown vendor id\n");
        return;
    }
    
    uh.dev_bus = libusb_get_bus_number(dev);
    uh.dev_addr = libusb_get_device_address(dev);
    
    if (already_registered(&uh)) {
        D("check_device(): Device (bus: %d, address: %d) "
          "is already registered\n", uh.dev_bus, uh.dev_addr);
        return;
    }
    
    D("check_device(): Device bus: %d, address: %d\n",
        uh.dev_bus, uh.dev_addr);

    r = libusb_get_active_config_descriptor(dev, &config);
    
    if (r != 0) {
        if (r == LIBUSB_ERROR_NOT_FOUND) {
            D("check_device(): Device %4x:%4x is unconfigured\n", 
                desc.idVendor, desc.idProduct);
            return;
        }
        
        D("check_device(): Failed to get configuration for %4x:%4x\n",
            desc.idVendor, desc.idProduct);
        return;
    }
    
    if (config == NULL) {
        D("check_device(): Sanity check failed after "
          "getting active config\n");
        return;
    }
    
    if (config->interface != NULL) {
        found = check_usb_interfaces(config, &desc, &uh);
    }
    
    /* not needed anymore */
    libusb_free_config_descriptor(config);
    
    r = libusb_open(dev, &uh.devh);
    uh.dev = dev;

    if (r != 0) {
        switch (r) {
            case LIBUSB_ERROR_NO_MEM:
                D("check_device(): Memory allocation problem\n");
                break;
                
            case LIBUSB_ERROR_ACCESS:
                D("check_device(): Permissions problem, "
                  "current user priveleges are messed up?\n");
                break;
                
            case LIBUSB_ERROR_NO_DEVICE:
                D("check_device(): Device disconected, bad cable?\n");
                break;
            
            default:
                D("check_device(): libusb triggered error %d\n", r);
        }
        // skip rest
        found = -1;
    }
    
    if (found >= 0) {
        D("check_device(): Device matches Android interface\n");
        // read the device's serial number
        memset(serial, 0, sizeof(serial));
        uh.interface = found;
        
        r = libusb_claim_interface(uh.devh, uh.interface);
        
        if (r < 0) {
            D("check_device(): Failed to claim interface %d\n",
                uh.interface);

            goto fail;
        }

        if (desc.iSerialNumber) {
            // reading serial
            uint16_t    buffer[128] = {0};
            uint16_t    languages[128] = {0};
            int languageCount = 0;

            memset(languages, 0, sizeof(languages));
            r = libusb_control_transfer(uh.devh, 
                LIBUSB_ENDPOINT_IN |  LIBUSB_REQUEST_TYPE_STANDARD | LIBUSB_RECIPIENT_DEVICE,
                LIBUSB_REQUEST_GET_DESCRIPTOR, LIBUSB_DT_STRING << 8,
		0, (uint8_t *)languages, sizeof(languages), 0);

            if (r <= 0) {
                D("check_device(): Failed to get languages count\n");
                goto fail;
            } 
            
            languageCount = (r - 2) / 2;
            
            for (i = 1; i <= languageCount; ++i) {
                memset(buffer, 0, sizeof(buffer));

                r = libusb_control_transfer(uh.devh, 
                    LIBUSB_ENDPOINT_IN |  LIBUSB_REQUEST_TYPE_STANDARD | LIBUSB_RECIPIENT_DEVICE,
                    LIBUSB_REQUEST_GET_DESCRIPTOR, (LIBUSB_DT_STRING << 8) | desc.iSerialNumber,
		    languages[i], (uint8_t *)buffer, sizeof(buffer), 0);
            
                if (r > 0) { /* converting serial */
                    int j = 0;
                    r /= 2;
                
                    for (j = 1; j < r; ++j)
                        serial[j - 1] = buffer[j];
                
                    serial[j - 1] = '\0';
                    break; /* languagesCount cycle */
                }
            }
            
            if (register_device(&uh, serial) == 0) {
                D("check_device(): Failed to register device\n");
                goto fail_interface;
            }
            
            libusb_ref_device(dev);
        }
    }
    
    return;

fail_interface:
    libusb_release_interface(uh.devh, uh.interface);

fail:
    libusb_close(uh.devh);
    uh.devh = NULL;
}

int
check_device_connected(struct usb_handle *uh)
{
    int r = libusb_kernel_driver_active(uh->devh, uh->interface);
    
    if (r == LIBUSB_ERROR_NO_DEVICE)
        return 0;
    
    if (r < 0)
        return -1;
    
    return 1;
}

void
kick_disconnected()
{
    struct usb_handle *usb= NULL;
    
    adb_mutex_lock(&usb_lock);

    for (usb = handle_list.next; usb != &handle_list; usb = usb->next) {
        
        if (check_device_connected(usb) == 0) {
            D("kick_disconnected(): Transport %p is not online anymore\n",
                usb);

            usb_kick(usb);
        }
    }
    
    adb_mutex_unlock(&usb_lock);
}

void
scan_usb_devices()
{
    D("scan_usb_devices(): started\n");
    
    libusb_device **devs= NULL;
    libusb_device *dev= NULL;
    ssize_t cnt = libusb_get_device_list(ctx, &devs);

    if (cnt < 0) {
        D("scan_usb_devices(): Failed to get device list (error: %d)\n",
            cnt);

        return;
    }
    
    int i = 0;

    while ((dev = devs[i++]) != NULL) {
        check_device(dev);
    }

    libusb_free_device_list(devs, 1);
}

void *
device_poll_thread(void* unused)
{
    D("device_poll_thread(): Created USB scan thread\n");
    
    for (;;) {
        sleep(5);
        kick_disconnected();
        scan_usb_devices();
    }

    /* never reaching this point */
    return (NULL);
}

static void
sigalrm_handler(int signo)
{
    /* nothing */
}

void
usb_init()
{
    D("usb_init(): started\n");
    adb_thread_t        tid;
    struct sigaction actions;

    int r = libusb_init(&ctx);

    if (r != LIBUSB_SUCCESS) {
        err(EX_IOERR, "Failed to init libusb\n");
    }

    memset(&actions, 0, sizeof(actions));
    
    sigemptyset(&actions.sa_mask);
    
    actions.sa_flags = 0;
    actions.sa_handler = sigalrm_handler;
    
    sigaction(SIGALRM, &actions, NULL);

	/* initial device scan */
	scan_usb_devices();
	
	/* starting USB event polling thread */
    if (adb_thread_create(&tid, device_poll_thread, NULL)) {
            err(EX_IOERR, "cannot create USB scan thread\n");
    }
    
    D("usb_init(): finished\n");
}


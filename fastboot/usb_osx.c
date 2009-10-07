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
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/IOCFPlugIn.h>
#include <IOKit/usb/IOUSBLib.h>
#include <IOKit/IOMessage.h>
#include <mach/mach_port.h>

#include "usb.h"


/*
 * Internal helper functions and associated definitions.
 */

#if TRACE_USB
#define WARN(x...) fprintf(stderr, x)
#else
#define WARN(x...)
#endif

#define ERR(x...) fprintf(stderr, "ERROR: " x)

/** An open usb device */
struct usb_handle
{
    int success;
    ifc_match_func callback;
    usb_ifc_info info;
    
    UInt8 bulkIn;
    UInt8 bulkOut;
    IOUSBInterfaceInterface190 **interface;
    unsigned int zero_mask;
};

/** Try out all the interfaces and see if there's a match. Returns 0 on
 * success, -1 on failure. */
static int try_interfaces(IOUSBDeviceInterface **dev, usb_handle *handle) {
    IOReturn kr;
    IOUSBFindInterfaceRequest request;
    io_iterator_t iterator;
    io_service_t usbInterface;
    IOCFPlugInInterface **plugInInterface;
    IOUSBInterfaceInterface190 **interface = NULL;
    HRESULT result;
    SInt32 score;
    UInt8 interfaceNumEndpoints;
    UInt8 endpoint;
    UInt8 configuration;

    // Placing the constant KIOUSBFindInterfaceDontCare into the following
    // fields of the IOUSBFindInterfaceRequest structure will allow us to
    // find all of the interfaces
    request.bInterfaceClass = kIOUSBFindInterfaceDontCare;
    request.bInterfaceSubClass = kIOUSBFindInterfaceDontCare;
    request.bInterfaceProtocol = kIOUSBFindInterfaceDontCare;
    request.bAlternateSetting = kIOUSBFindInterfaceDontCare;

    // SetConfiguration will kill an existing UMS connection, so let's
    // not do this if not necessary.
    configuration = 0;
    (*dev)->GetConfiguration(dev, &configuration);
    if (configuration != 1)
        (*dev)->SetConfiguration(dev, 1);

    // Get an iterator for the interfaces on the device
    kr = (*dev)->CreateInterfaceIterator(dev, &request, &iterator);

    if (kr != 0) {
        ERR("Couldn't create a device interface iterator: (%08x)\n", kr);
        return -1;
    }

    while ((usbInterface = IOIteratorNext(iterator))) {
        // Create an intermediate plugin
        kr = IOCreatePlugInInterfaceForService(
                usbInterface,
                kIOUSBInterfaceUserClientTypeID,
                kIOCFPlugInInterfaceID,
                &plugInInterface,
                &score);

        // No longer need the usbInterface object now that we have the plugin
        (void) IOObjectRelease(usbInterface);

        if ((kr != 0) || (!plugInInterface)) {
            WARN("Unable to create plugin (%08x)\n", kr);
            continue;
        }

        // Now create the interface interface for the interface
        result = (*plugInInterface)->QueryInterface(
                plugInInterface,
                CFUUIDGetUUIDBytes(kIOUSBInterfaceInterfaceID),
                (LPVOID) &interface);

        // No longer need the intermediate plugin
        (*plugInInterface)->Release(plugInInterface);

        if (result || !interface) {
            ERR("Couldn't create interface interface: (%08x)\n",
               (unsigned int) result);
            // continue so we can try the next interface
            continue;
        }
        
        /*
         * Now open the interface. This will cause the pipes
         * associated with the endpoints in the interface descriptor
         * to be instantiated.
         */

        /*
         * TODO: Earlier comments here indicated that it was a bad
         * idea to just open any interface, because opening "mass
         * storage endpoints" is bad. However, the only way to find
         * out if an interface does bulk in or out is to open it, and
         * the framework in this application wants to be told about
         * bulk in / out before deciding whether it actually wants to
         * use the interface. Maybe something needs to be done about
         * this situation.
         */
        
        kr = (*interface)->USBInterfaceOpen(interface);

        if (kr != 0) {
            WARN("Could not open interface: (%08x)\n", kr);
            (void) (*interface)->Release(interface);
            // continue so we can try the next interface
            continue;
        }
        
        // Get the number of endpoints associated with this interface.
        kr = (*interface)->GetNumEndpoints(interface, &interfaceNumEndpoints);

        if (kr != 0) {
            ERR("Unable to get number of endpoints: (%08x)\n", kr);
            goto next_interface;
        }

        // Get interface class, subclass and protocol
        if ((*interface)->GetInterfaceClass(interface, &handle->info.ifc_class) != 0 ||
            (*interface)->GetInterfaceSubClass(interface, &handle->info.ifc_subclass) != 0 ||
            (*interface)->GetInterfaceProtocol(interface, &handle->info.ifc_protocol) != 0)
        {
            ERR("Unable to get interface class, subclass and protocol\n");
            goto next_interface;
        }

        handle->info.has_bulk_in = 0;
        handle->info.has_bulk_out = 0;

        // Iterate over the endpoints for this interface and see if there
        // are any that do bulk in/out.
        for (endpoint = 0; endpoint <= interfaceNumEndpoints; endpoint++) {
            UInt8   transferType;
            UInt16  maxPacketSize;
            UInt8   interval;
            UInt8   number;
            UInt8   direction;

            kr = (*interface)->GetPipeProperties(interface, endpoint,
                    &direction,
                    &number, &transferType, &maxPacketSize, &interval);

            if (kr == 0) {
                if (transferType != kUSBBulk) {
                    continue;
                }

                if (direction == kUSBIn) {
                    handle->info.has_bulk_in = 1;
                    handle->bulkIn = endpoint;
                } else if (direction == kUSBOut) {
                    handle->info.has_bulk_out = 1;
                    handle->bulkOut = endpoint;
                }

                if (handle->info.ifc_protocol == 0x01) {
                    handle->zero_mask = maxPacketSize - 1;
                }
            } else {
                ERR("could not get pipe properties\n");
            }

            if (handle->info.has_bulk_in && handle->info.has_bulk_out) {
                break;
            }
        }

        if (handle->callback(&handle->info) == 0) {
            handle->interface = interface;
            handle->success = 1;

            /*
             * Clear both the endpoints, because it has been observed
             * that the Mac may otherwise (incorrectly) start out with
             * them in bad state.
             */

            if (handle->info.has_bulk_in) {
                kr = (*interface)->ClearPipeStallBothEnds(interface,
                        handle->bulkIn);
                if (kr != 0) {
                    ERR("could not clear input pipe; result %d", kr);
                    return -1;
                }
            }

            if (handle->info.has_bulk_out) {
                kr = (*interface)->ClearPipeStallBothEnds(interface,
                        handle->bulkOut);
                if (kr != 0) {
                    ERR("could not clear output pipe; result %d", kr);
                    return -1;
                }
            }
            
            return 0;
        }
        
next_interface:
        (*interface)->USBInterfaceClose(interface);
        (*interface)->Release(interface);
    }

    return 0;
}

/** Try out the given device and see if there's a match. Returns 0 on
 * success, -1 on failure.
 */
static int try_device(io_service_t device, usb_handle *handle) {
    kern_return_t kr;
    IOCFPlugInInterface **plugin = NULL;
    IOUSBDeviceInterface182 **dev = NULL;
    SInt32 score;
    HRESULT result;
    UInt8 serialIndex;

    // Create an intermediate plugin.
    kr = IOCreatePlugInInterfaceForService(device,
            kIOUSBDeviceUserClientTypeID,
            kIOCFPlugInInterfaceID,
            &plugin, &score);

    if ((kr != 0) || (plugin == NULL)) {
        ERR("Unable to create a plug-in (%08x)\n", kr);
        goto error;
    }

    // Now create the device interface.
    result = (*plugin)->QueryInterface(plugin,
            CFUUIDGetUUIDBytes(kIOUSBDeviceInterfaceID), (LPVOID) &dev);
    if ((result != 0) || (dev == NULL)) {
        ERR("Couldn't create a device interface (%08x)\n", (int) result);
        goto error;
    }

    /* 
     * We don't need the intermediate interface after the device interface
     * is created.
     */
    IODestroyPlugInInterface(plugin);

    // So, we have a device, finally. Grab its vitals.

    kr = (*dev)->GetDeviceVendor(dev, &handle->info.dev_vendor);
    if (kr != 0) {
        ERR("GetDeviceVendor");
        goto error;
    }

    kr = (*dev)->GetDeviceProduct(dev, &handle->info.dev_product);
    if (kr != 0) {
        ERR("GetDeviceProduct");
        goto error;
    }

    kr = (*dev)->GetDeviceClass(dev, &handle->info.dev_class);
    if (kr != 0) {
        ERR("GetDeviceClass");
        goto error;
    }

    kr = (*dev)->GetDeviceSubClass(dev, &handle->info.dev_subclass);
    if (kr != 0) {
        ERR("GetDeviceSubClass");
        goto error;
    }

    kr = (*dev)->GetDeviceProtocol(dev, &handle->info.dev_protocol);
    if (kr != 0) {
        ERR("GetDeviceProtocol");
        goto error;
    }

    kr = (*dev)->USBGetSerialNumberStringIndex(dev, &serialIndex);

    if (serialIndex > 0) {
        IOUSBDevRequest req;
        UInt16  buffer[256];

        req.bmRequestType = USBmakebmRequestType(kUSBIn, kUSBStandard, kUSBDevice);
        req.bRequest = kUSBRqGetDescriptor;
        req.wValue = (kUSBStringDesc << 8) | serialIndex;
        req.wIndex = 0;
        req.pData = buffer;
        req.wLength = sizeof(buffer);
        kr = (*dev)->DeviceRequest(dev, &req);

        if (kr == kIOReturnSuccess && req.wLenDone > 0) {
            int i, count;
            
            // skip first word, and copy the rest to the serial string, changing shorts to bytes.
            count = (req.wLenDone - 1) / 2;
            for (i = 0; i < count; i++)
              handle->info.serial_number[i] = buffer[i + 1];
            handle->info.serial_number[i] = 0;
        }
    } else {
        // device has no serial number
        handle->info.serial_number[0] = 0;
    }
    handle->info.writable = 1;

    if (try_interfaces(dev, handle)) {
        goto error;
    }

    (*dev)->Release(dev);
    return 0;

    error:

    if (dev != NULL) {
        (*dev)->Release(dev);
    }
    
    return -1;    
}


/** Initializes the USB system. Returns 0 on success, -1 on error. */
static int init_usb(ifc_match_func callback, usb_handle **handle) {
    int ret = -1;
    CFMutableDictionaryRef matchingDict;
    kern_return_t result;
    io_iterator_t iterator;
    usb_handle h;

    h.success = 0;
    h.callback = callback;

    /*
     * Create our matching dictionary to find appropriate devices.
     * IOServiceAddMatchingNotification consumes the reference, so we
     * do not need to release it.
     */
    matchingDict = IOServiceMatching(kIOUSBDeviceClassName);

    if (matchingDict == NULL) {
        ERR("Couldn't create USB matching dictionary.\n");
        return -1;
    }

    result = IOServiceGetMatchingServices(
            kIOMasterPortDefault, matchingDict, &iterator);

    if (result != 0) {
        ERR("Could not create iterator.");
        return -1;
    }
    
    for (;;) {
        if (! IOIteratorIsValid(iterator)) {
            /*
             * Apple documentation advises resetting the iterator if
             * it should become invalid during iteration.
             */
            IOIteratorReset(iterator);
            continue;
        }
                
        io_service_t device = IOIteratorNext(iterator);

        if (device == 0) {
            break;
        }

        if (try_device(device, &h) != 0) {
            IOObjectRelease(device);
            ret = -1;
            break;
        }

        if (h.success) {
            *handle = calloc(1, sizeof(usb_handle));
            memcpy(*handle, &h, sizeof(usb_handle));
            ret = 0;
            break;
        }

        IOObjectRelease(device);
    }

    IOObjectRelease(iterator);

    return ret;
}



/*
 * Definitions of this file's public functions.
 */

usb_handle *usb_open(ifc_match_func callback) {
    usb_handle *handle = NULL;

    if (init_usb(callback, &handle) < 0) {
        /* Something went wrong initializing USB. */
        return NULL;
    }

    return handle;
}

int usb_close(usb_handle *h) {
    /* TODO: Something better here? */
    return 0;
}

int usb_read(usb_handle *h, void *data, int len) {
    IOReturn result;
    UInt32 numBytes = len;

    if (len == 0) {
        return 0;
    }

    if (h == NULL) {
        return -1;
    }

    if (h->interface == NULL) {
        ERR("usb_read interface was null\n");
        return -1;
    }

    if (h->bulkIn == 0) {
        ERR("bulkIn endpoint not assigned\n");
        return -1;
    }

    result = (*h->interface)->ReadPipe(
            h->interface, h->bulkIn, data, &numBytes);

    if (result == 0) {
        return (int) numBytes;
    } else {
        ERR("usb_read failed with status %x\n", result);
    }

    return -1;
}

int usb_write(usb_handle *h, const void *data, int len) {
    IOReturn result;

    if (len == 0) {
        return 0;
    }

    if (h == NULL) {
        return -1;
    }

    if (h->interface == NULL) {
        ERR("usb_write interface was null\n");
        return -1;
    }

    if (h->bulkOut == 0) {
        ERR("bulkOut endpoint not assigned\n");
        return -1;
    }

    result = (*h->interface)->WritePipe(
            h->interface, h->bulkOut, (void *)data, len);

    #if 0
    if ((result == 0) && (h->zero_mask)) {
        /* we need 0-markers and our transfer */
        if(!(len & h->zero_mask)) {
            result = (*h->interface)->WritePipe(
                    h->interface, h->bulkOut, (void *)data, 0);
        }
    }
    #endif

    if (result != 0) {
        ERR("usb_write failed with status %x\n", result);
        return -1;
    }

    return len;
}

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

#include <CoreFoundation/CoreFoundation.h>

#include <IOKit/IOKitLib.h>
#include <IOKit/IOCFPlugIn.h>
#include <IOKit/usb/IOUSBLib.h>
#include <IOKit/IOMessage.h>
#include <mach/mach_port.h>

#include "sysdeps.h"

#include <stdio.h>

#define TRACE_TAG   TRACE_USB
#include "adb.h"
#include "usb_vendors.h"

#define  DBG   D

static IONotificationPortRef    notificationPort = 0;
static io_iterator_t*           notificationIterators;

struct usb_handle
{
    UInt8                     bulkIn;
    UInt8                     bulkOut;
    IOUSBInterfaceInterface   **interface;
    io_object_t               usbNotification;
    unsigned int              zero_mask;
};

static CFRunLoopRef currentRunLoop = 0;
static pthread_mutex_t start_lock;
static pthread_cond_t start_cond;


static void AndroidInterfaceAdded(void *refCon, io_iterator_t iterator);
static void AndroidInterfaceNotify(void *refCon, io_iterator_t iterator,
                                   natural_t messageType,
                                   void *messageArgument);
static usb_handle* CheckInterface(IOUSBInterfaceInterface **iface,
                                  UInt16 vendor, UInt16 product);

static int
InitUSB()
{
    CFMutableDictionaryRef  matchingDict;
    CFRunLoopSourceRef      runLoopSource;
    SInt32                  vendor, if_subclass, if_protocol;
    unsigned                i;

    //* To set up asynchronous notifications, create a notification port and
    //* add its run loop event source to the program's run loop
    notificationPort = IONotificationPortCreate(kIOMasterPortDefault);
    runLoopSource = IONotificationPortGetRunLoopSource(notificationPort);
    CFRunLoopAddSource(CFRunLoopGetCurrent(), runLoopSource, kCFRunLoopDefaultMode);

    memset(notificationIterators, 0, sizeof(notificationIterators));

    //* loop through all supported vendors
    for (i = 0; i < vendorIdCount; i++) {
        //* Create our matching dictionary to find the Android device's
        //* adb interface
        //* IOServiceAddMatchingNotification consumes the reference, so we do
        //* not need to release this
        matchingDict = IOServiceMatching(kIOUSBInterfaceClassName);

        if (!matchingDict) {
            DBG("ERR: Couldn't create USB matching dictionary.\n");
            return -1;
        }

        //* Match based on vendor id, interface subclass and protocol
        vendor = vendorIds[i];
        if_subclass = ADB_SUBCLASS;
        if_protocol = ADB_PROTOCOL;
        CFDictionarySetValue(matchingDict, CFSTR(kUSBVendorID),
                             CFNumberCreate(kCFAllocatorDefault,
                                            kCFNumberSInt32Type, &vendor));
        CFDictionarySetValue(matchingDict, CFSTR(kUSBInterfaceSubClass),
                             CFNumberCreate(kCFAllocatorDefault,
                                            kCFNumberSInt32Type, &if_subclass));
        CFDictionarySetValue(matchingDict, CFSTR(kUSBInterfaceProtocol),
                             CFNumberCreate(kCFAllocatorDefault,
                                            kCFNumberSInt32Type, &if_protocol));
        IOServiceAddMatchingNotification(
                notificationPort,
                kIOFirstMatchNotification,
                matchingDict,
                AndroidInterfaceAdded,
                NULL,
                &notificationIterators[i]);

        //* Iterate over set of matching interfaces to access already-present
        //* devices and to arm the notification
        AndroidInterfaceAdded(NULL, notificationIterators[i]);
    }

    return 0;
}

static void
AndroidInterfaceAdded(void *refCon, io_iterator_t iterator)
{
    kern_return_t            kr;
    io_service_t             usbDevice;
    io_service_t             usbInterface;
    IOCFPlugInInterface      **plugInInterface = NULL;
    IOUSBInterfaceInterface220  **iface = NULL;
    IOUSBDeviceInterface197  **dev = NULL;
    HRESULT                  result;
    SInt32                   score;
    UInt16                   vendor;
    UInt16                   product;
    UInt8                    serialIndex;
    char                     serial[256];

    while ((usbInterface = IOIteratorNext(iterator))) {
        //* Create an intermediate interface plugin
        kr = IOCreatePlugInInterfaceForService(usbInterface,
                                               kIOUSBInterfaceUserClientTypeID,
                                               kIOCFPlugInInterfaceID,
                                               &plugInInterface, &score);
        IOObjectRelease(usbInterface);
        if ((kIOReturnSuccess != kr) || (!plugInInterface)) {
            DBG("ERR: Unable to create an interface plug-in (%08x)\n", kr);
            continue;
        }

        //* This gets us the interface object
        result = (*plugInInterface)->QueryInterface(plugInInterface,
                CFUUIDGetUUIDBytes(kIOUSBInterfaceInterfaceID), (LPVOID)
                &iface);
        //* We only needed the plugin to get the interface, so discard it
        (*plugInInterface)->Release(plugInInterface);
        if (result || !iface) {
            DBG("ERR: Couldn't query the interface (%08x)\n", (int) result);
            continue;
        }

        //* this gets us an ioservice, with which we will find the actual
        //* device; after getting a plugin, and querying the interface, of
        //* course.
        //* Gotta love OS X
        kr = (*iface)->GetDevice(iface, &usbDevice);
        if (kIOReturnSuccess != kr || !usbDevice) {
            DBG("ERR: Couldn't grab device from interface (%08x)\n", kr);
            continue;
        }

        plugInInterface = NULL;
        score = 0;
        //* create an intermediate device plugin
        kr = IOCreatePlugInInterfaceForService(usbDevice,
                                               kIOUSBDeviceUserClientTypeID,
                                               kIOCFPlugInInterfaceID,
                                               &plugInInterface, &score);
        //* only needed this to find the plugin
        (void)IOObjectRelease(usbDevice);
        if ((kIOReturnSuccess != kr) || (!plugInInterface)) {
            DBG("ERR: Unable to create a device plug-in (%08x)\n", kr);
            continue;
        }

        result = (*plugInInterface)->QueryInterface(plugInInterface,
                CFUUIDGetUUIDBytes(kIOUSBDeviceInterfaceID), (LPVOID) &dev);
        //* only needed this to query the plugin
        (*plugInInterface)->Release(plugInInterface);
        if (result || !dev) {
            DBG("ERR: Couldn't create a device interface (%08x)\n",
                (int) result);
            continue;
        }

        //* Now after all that, we actually have a ref to the device and
        //* the interface that matched our criteria

        kr = (*dev)->GetDeviceVendor(dev, &vendor);
        kr = (*dev)->GetDeviceProduct(dev, &product);
        kr = (*dev)->USBGetSerialNumberStringIndex(dev, &serialIndex);

	if (serialIndex > 0) {
		IOUSBDevRequest req;
		UInt16          buffer[256];
		UInt16          languages[128];

		memset(languages, 0, sizeof(languages));

		req.bmRequestType =
			USBmakebmRequestType(kUSBIn, kUSBStandard, kUSBDevice);
		req.bRequest = kUSBRqGetDescriptor;
		req.wValue = (kUSBStringDesc << 8) | 0;
		req.wIndex = 0;
		req.pData = languages;
		req.wLength = sizeof(languages);
		kr = (*dev)->DeviceRequest(dev, &req);

		if (kr == kIOReturnSuccess && req.wLenDone > 0) {

			int langCount = (req.wLenDone - 2) / 2, lang;

			for (lang = 1; lang <= langCount; lang++) {

                                memset(buffer, 0, sizeof(buffer));
                                memset(&req, 0, sizeof(req));

				req.bmRequestType =
					USBmakebmRequestType(kUSBIn, kUSBStandard, kUSBDevice);
				req.bRequest = kUSBRqGetDescriptor;
				req.wValue = (kUSBStringDesc << 8) | serialIndex;
				req.wIndex = languages[lang];
				req.pData = buffer;
				req.wLength = sizeof(buffer);
				kr = (*dev)->DeviceRequest(dev, &req);

				if (kr == kIOReturnSuccess && req.wLenDone > 0) {
					int i, count;

					// skip first word, and copy the rest to the serial string,
					// changing shorts to bytes.
					count = (req.wLenDone - 1) / 2;
					for (i = 0; i < count; i++)
						serial[i] = buffer[i + 1];
					serial[i] = 0;
                                        break;
				}
			}
		}
	}
        (*dev)->Release(dev);

        DBG("INFO: Found vid=%04x pid=%04x serial=%s\n", vendor, product,
            serial);

        usb_handle* handle = CheckInterface((IOUSBInterfaceInterface**)iface,
                                            vendor, product);
        if (handle == NULL) {
            DBG("ERR: Could not find device interface: %08x\n", kr);
            (*iface)->Release(iface);
            continue;
        }

        DBG("AndroidDeviceAdded calling register_usb_transport\n");
        register_usb_transport(handle, (serial[0] ? serial : NULL), 1);

        // Register for an interest notification of this device being removed.
        // Pass the reference to our private data as the refCon for the
        // notification.
        kr = IOServiceAddInterestNotification(notificationPort,
                usbInterface,
                kIOGeneralInterest,
                AndroidInterfaceNotify,
                handle,
                &handle->usbNotification);

        if (kIOReturnSuccess != kr) {
            DBG("ERR: Unable to create interest notification (%08x)\n", kr);
        }
    }
}

static void
AndroidInterfaceNotify(void *refCon, io_service_t service, natural_t messageType, void *messageArgument)
{
    usb_handle *handle = (usb_handle *)refCon;

    if (messageType == kIOMessageServiceIsTerminated) {
        if (!handle) {
            DBG("ERR: NULL handle\n");
            return;
        }
        DBG("AndroidInterfaceNotify\n");
        IOObjectRelease(handle->usbNotification);
        usb_kick(handle);
    }
}

//* TODO: simplify this further since we only register to get ADB interface
//* subclass+protocol events
static usb_handle*
CheckInterface(IOUSBInterfaceInterface **interface, UInt16 vendor, UInt16 product)
{
    usb_handle*                 handle = NULL;
    IOReturn                    kr;
    UInt8  interfaceNumEndpoints, interfaceClass, interfaceSubClass, interfaceProtocol;
    UInt8  endpoint;


    //* Now open the interface.  This will cause the pipes associated with
    //* the endpoints in the interface descriptor to be instantiated
    kr = (*interface)->USBInterfaceOpen(interface);
    if (kr != kIOReturnSuccess) {
        DBG("ERR: Could not open interface: (%08x)\n", kr);
        return NULL;
    }

    //* Get the number of endpoints associated with this interface
    kr = (*interface)->GetNumEndpoints(interface, &interfaceNumEndpoints);
    if (kr != kIOReturnSuccess) {
        DBG("ERR: Unable to get number of endpoints: (%08x)\n", kr);
        goto err_get_num_ep;
    }

    //* Get interface class, subclass and protocol
    if ((*interface)->GetInterfaceClass(interface, &interfaceClass) != kIOReturnSuccess ||
            (*interface)->GetInterfaceSubClass(interface, &interfaceSubClass) != kIOReturnSuccess ||
            (*interface)->GetInterfaceProtocol(interface, &interfaceProtocol) != kIOReturnSuccess) {
            DBG("ERR: Unable to get interface class, subclass and protocol\n");
            goto err_get_interface_class;
    }

    //* check to make sure interface class, subclass and protocol match ADB
    //* avoid opening mass storage endpoints
    if (!is_adb_interface(vendor, product, interfaceClass,
                interfaceSubClass, interfaceProtocol))
        goto err_bad_adb_interface;

    handle = calloc(1, sizeof(usb_handle));

    //* Iterate over the endpoints for this interface and find the first
    //* bulk in/out pipes available.  These will be our read/write pipes.
    for (endpoint = 0; endpoint <= interfaceNumEndpoints; endpoint++) {
        UInt8   transferType;
        UInt16  maxPacketSize;
        UInt8   interval;
        UInt8   number;
        UInt8   direction;

        kr = (*interface)->GetPipeProperties(interface, endpoint, &direction,
                &number, &transferType, &maxPacketSize, &interval);

        if (kIOReturnSuccess == kr) {
            if (kUSBBulk != transferType)
                continue;

            if (kUSBIn == direction)
                handle->bulkIn = endpoint;

            if (kUSBOut == direction)
                handle->bulkOut = endpoint;

            handle->zero_mask = maxPacketSize - 1;
        } else {
            DBG("ERR: FindDeviceInterface - could not get pipe properties\n");
            goto err_get_pipe_props;
        }
    }

    handle->interface = interface;
    return handle;

err_get_pipe_props:
    free(handle);
err_bad_adb_interface:
err_get_interface_class:
err_get_num_ep:
    (*interface)->USBInterfaceClose(interface);
    return NULL;
}


void* RunLoopThread(void* unused)
{
    unsigned i;

    InitUSB();

    currentRunLoop = CFRunLoopGetCurrent();

    // Signal the parent that we are running
    adb_mutex_lock(&start_lock);
    adb_cond_signal(&start_cond);
    adb_mutex_unlock(&start_lock);

    CFRunLoopRun();
    currentRunLoop = 0;

    for (i = 0; i < vendorIdCount; i++) {
        IOObjectRelease(notificationIterators[i]);
    }
    IONotificationPortDestroy(notificationPort);

    DBG("RunLoopThread done\n");
    return NULL;    
}


static int initialized = 0;
void usb_init()
{
    if (!initialized)
    {
        adb_thread_t    tid;

        notificationIterators = (io_iterator_t*)malloc(
            vendorIdCount * sizeof(io_iterator_t));

        adb_mutex_init(&start_lock, NULL);
        adb_cond_init(&start_cond, NULL);

        if(adb_thread_create(&tid, RunLoopThread, NULL))
            fatal_errno("cannot create input thread");

        // Wait for initialization to finish
        adb_mutex_lock(&start_lock);
        adb_cond_wait(&start_cond, &start_lock);
        adb_mutex_unlock(&start_lock);

        adb_mutex_destroy(&start_lock);
        adb_cond_destroy(&start_cond);

        initialized = 1;
    }
}

void usb_cleanup()
{
    DBG("usb_cleanup\n");
    close_usb_devices();
    if (currentRunLoop)
        CFRunLoopStop(currentRunLoop);

    if (notificationIterators != NULL) {
        free(notificationIterators);
        notificationIterators = NULL;
    }
}

int usb_write(usb_handle *handle, const void *buf, int len)
{
    IOReturn    result;

    if (!len)
        return 0;

    if (!handle)
        return -1;

    if (NULL == handle->interface) {
        DBG("ERR: usb_write interface was null\n");
        return -1;
    }

    if (0 == handle->bulkOut) {
        DBG("ERR: bulkOut endpoint not assigned\n");
        return -1;
    }

    result =
        (*handle->interface)->WritePipe(
                              handle->interface, handle->bulkOut, (void *)buf, len);

    if ((result == 0) && (handle->zero_mask)) {
        /* we need 0-markers and our transfer */
        if(!(len & handle->zero_mask)) {
            result =
                (*handle->interface)->WritePipe(
                        handle->interface, handle->bulkOut, (void *)buf, 0);
        }
    }

    if (0 == result)
        return 0;

    DBG("ERR: usb_write failed with status %d\n", result);
    return -1;
}

int usb_read(usb_handle *handle, void *buf, int len)
{
    IOReturn result;
    UInt32  numBytes = len;

    if (!len) {
        return 0;
    }

    if (!handle) {
        return -1;
    }

    if (NULL == handle->interface) {
        DBG("ERR: usb_read interface was null\n");
        return -1;
    }

    if (0 == handle->bulkIn) {
        DBG("ERR: bulkIn endpoint not assigned\n");
        return -1;
    }

    result =
      (*handle->interface)->ReadPipe(handle->interface,
                                    handle->bulkIn, buf, &numBytes);

    if (0 == result)
        return 0;
    else {
        DBG("ERR: usb_read failed with status %d\n", result);
    }

    return -1;
}

int usb_close(usb_handle *handle)
{
    return 0;
}

void usb_kick(usb_handle *handle)
{
    /* release the interface */
    if (!handle)
        return;

    if (handle->interface)
    {
        (*handle->interface)->USBInterfaceClose(handle->interface);
        (*handle->interface)->Release(handle->interface);
        handle->interface = 0;
    }
}

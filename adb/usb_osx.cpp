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

#include <CoreFoundation/CoreFoundation.h>

#include <IOKit/IOKitLib.h>
#include <IOKit/IOCFPlugIn.h>
#include <IOKit/usb/IOUSBLib.h>
#include <IOKit/IOMessage.h>
#include <mach/mach_port.h>

#include <inttypes.h>
#include <stdio.h>

#include <atomic>
#include <memory>
#include <mutex>
#include <vector>

#include <android-base/logging.h>
#include <android-base/stringprintf.h>

#include "adb.h"
#include "transport.h"

struct usb_handle
{
    UInt8 bulkIn;
    UInt8 bulkOut;
    IOUSBInterfaceInterface190** interface;
    unsigned int zero_mask;

    // For garbage collecting disconnected devices.
    bool mark;
    std::string devpath;
    std::atomic<bool> dead;

    usb_handle() : bulkIn(0), bulkOut(0), interface(nullptr),
        zero_mask(0), mark(false), dead(false) {
    }
};

static std::atomic<bool> usb_inited_flag;

static auto& g_usb_handles_mutex = *new std::mutex();
static auto& g_usb_handles = *new std::vector<std::unique_ptr<usb_handle>>();

static bool IsKnownDevice(const std::string& devpath) {
    std::lock_guard<std::mutex> lock_guard(g_usb_handles_mutex);
    for (auto& usb : g_usb_handles) {
        if (usb->devpath == devpath) {
            // Set mark flag to indicate this device is still alive.
            usb->mark = true;
            return true;
        }
    }
    return false;
}

static void usb_kick_locked(usb_handle* handle);

static void KickDisconnectedDevices() {
    std::lock_guard<std::mutex> lock_guard(g_usb_handles_mutex);
    for (auto& usb : g_usb_handles) {
        if (!usb->mark) {
            usb_kick_locked(usb.get());
        } else {
            usb->mark = false;
        }
    }
}

static void AddDevice(std::unique_ptr<usb_handle> handle) {
    handle->mark = true;
    std::lock_guard<std::mutex> lock(g_usb_handles_mutex);
    g_usb_handles.push_back(std::move(handle));
}

static void AndroidInterfaceAdded(io_iterator_t iterator);
static std::unique_ptr<usb_handle> CheckInterface(IOUSBInterfaceInterface190 **iface,
                                                  UInt16 vendor, UInt16 product);

static bool FindUSBDevices() {
    // Create the matching dictionary to find the Android device's adb interface.
    CFMutableDictionaryRef matchingDict = IOServiceMatching(kIOUSBInterfaceClassName);
    if (!matchingDict) {
        LOG(ERROR) << "couldn't create USB matching dictionary";
        return false;
    }
    // Create an iterator for all I/O Registry objects that match the dictionary.
    io_iterator_t iter = 0;
    kern_return_t kr = IOServiceGetMatchingServices(kIOMasterPortDefault, matchingDict, &iter);
    if (kr != KERN_SUCCESS) {
        LOG(ERROR) << "failed to get matching services";
        return false;
    }
    // Iterate over all matching objects.
    AndroidInterfaceAdded(iter);
    IOObjectRelease(iter);
    return true;
}

static void
AndroidInterfaceAdded(io_iterator_t iterator)
{
    kern_return_t            kr;
    io_service_t             usbDevice;
    io_service_t             usbInterface;
    IOCFPlugInInterface      **plugInInterface = NULL;
    IOUSBInterfaceInterface220  **iface = NULL;
    IOUSBDeviceInterface197  **dev = NULL;
    HRESULT                  result;
    SInt32                   score;
    uint32_t                 locationId;
    UInt8                    if_class, subclass, protocol;
    UInt16                   vendor;
    UInt16                   product;
    UInt8                    serialIndex;
    char                     serial[256];
    std::string devpath;

    while ((usbInterface = IOIteratorNext(iterator))) {
        //* Create an intermediate interface plugin
        kr = IOCreatePlugInInterfaceForService(usbInterface,
                                               kIOUSBInterfaceUserClientTypeID,
                                               kIOCFPlugInInterfaceID,
                                               &plugInInterface, &score);
        IOObjectRelease(usbInterface);
        if ((kIOReturnSuccess != kr) || (!plugInInterface)) {
            LOG(ERROR) << "Unable to create an interface plug-in (" << std::hex << kr << ")";
            continue;
        }

        //* This gets us the interface object
        result = (*plugInInterface)->QueryInterface(
            plugInInterface,
            CFUUIDGetUUIDBytes(kIOUSBInterfaceInterfaceID), (LPVOID*)&iface);
        //* We only needed the plugin to get the interface, so discard it
        (*plugInInterface)->Release(plugInInterface);
        if (result || !iface) {
            LOG(ERROR) << "Couldn't query the interface (" << std::hex << result << ")";
            continue;
        }

        kr = (*iface)->GetInterfaceClass(iface, &if_class);
        kr = (*iface)->GetInterfaceSubClass(iface, &subclass);
        kr = (*iface)->GetInterfaceProtocol(iface, &protocol);
        if(if_class != ADB_CLASS || subclass != ADB_SUBCLASS || protocol != ADB_PROTOCOL) {
            // Ignore non-ADB devices.
            LOG(DEBUG) << "Ignoring interface with incorrect class/subclass/protocol - " << if_class
                       << ", " << subclass << ", " << protocol;
            (*iface)->Release(iface);
            continue;
        }

        //* this gets us an ioservice, with which we will find the actual
        //* device; after getting a plugin, and querying the interface, of
        //* course.
        //* Gotta love OS X
        kr = (*iface)->GetDevice(iface, &usbDevice);
        if (kIOReturnSuccess != kr || !usbDevice) {
            LOG(ERROR) << "Couldn't grab device from interface (" << std::hex << kr << ")";
            (*iface)->Release(iface);
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
            LOG(ERROR) << "Unable to create a device plug-in (" << std::hex << kr << ")";
            (*iface)->Release(iface);
            continue;
        }

        result = (*plugInInterface)->QueryInterface(plugInInterface,
            CFUUIDGetUUIDBytes(kIOUSBDeviceInterfaceID), (LPVOID*)&dev);
        //* only needed this to query the plugin
        (*plugInInterface)->Release(plugInInterface);
        if (result || !dev) {
            LOG(ERROR) << "Couldn't create a device interface (" << std::hex << result << ")";
            (*iface)->Release(iface);
            continue;
        }

        //* Now after all that, we actually have a ref to the device and
        //* the interface that matched our criteria
        kr = (*dev)->GetDeviceVendor(dev, &vendor);
        kr = (*dev)->GetDeviceProduct(dev, &product);
        kr = (*dev)->GetLocationID(dev, &locationId);
        if (kr == KERN_SUCCESS) {
            devpath = android::base::StringPrintf("usb:%" PRIu32 "X", locationId);
            if (IsKnownDevice(devpath)) {
                (*dev)->Release(dev);
                (*iface)->Release(iface);
                continue;
            }
        }
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

        VLOG(USB) << android::base::StringPrintf("Found vid=%04x pid=%04x serial=%s\n",
                        vendor, product, serial);
        if (devpath.empty()) {
            devpath = serial;
        }
        if (IsKnownDevice(devpath)) {
            (*iface)->USBInterfaceClose(iface);
            (*iface)->Release(iface);
            continue;
        }

        std::unique_ptr<usb_handle> handle = CheckInterface((IOUSBInterfaceInterface190**)iface,
                                                            vendor, product);
        if (handle == nullptr) {
            LOG(ERROR) << "Could not find device interface";
            (*iface)->Release(iface);
            continue;
        }
        handle->devpath = devpath;
        usb_handle* handle_p = handle.get();
        VLOG(USB) << "Add usb device " << serial;
        AddDevice(std::move(handle));
        register_usb_transport(handle_p, serial, devpath.c_str(), 1);
    }
}

// Used to clear both the endpoints before starting.
// When adb quits, we might clear the host endpoint but not the device.
// So we make sure both sides are clear before starting up.
static bool ClearPipeStallBothEnds(IOUSBInterfaceInterface190** interface, UInt8 bulkEp) {
    IOReturn rc = (*interface)->ClearPipeStallBothEnds(interface, bulkEp);
    if (rc != kIOReturnSuccess) {
        LOG(ERROR) << "Could not clear pipe stall both ends: " << std::hex << rc;
        return false;
    }
    return true;
}

//* TODO: simplify this further since we only register to get ADB interface
//* subclass+protocol events
static std::unique_ptr<usb_handle>
CheckInterface(IOUSBInterfaceInterface190 **interface, UInt16 vendor, UInt16 product)
{
    std::unique_ptr<usb_handle> handle;
    IOReturn kr;
    UInt8 interfaceNumEndpoints, interfaceClass, interfaceSubClass, interfaceProtocol;
    UInt8 endpoint;

    //* Now open the interface.  This will cause the pipes associated with
    //* the endpoints in the interface descriptor to be instantiated
    kr = (*interface)->USBInterfaceOpen(interface);
    if (kr != kIOReturnSuccess) {
        LOG(ERROR) << "Could not open interface: " << std::hex << kr;
        return NULL;
    }

    //* Get the number of endpoints associated with this interface
    kr = (*interface)->GetNumEndpoints(interface, &interfaceNumEndpoints);
    if (kr != kIOReturnSuccess) {
        LOG(ERROR) << "Unable to get number of endpoints: " << std::hex << kr;
        goto err_get_num_ep;
    }

    //* Get interface class, subclass and protocol
    if ((*interface)->GetInterfaceClass(interface, &interfaceClass) != kIOReturnSuccess ||
            (*interface)->GetInterfaceSubClass(interface, &interfaceSubClass) != kIOReturnSuccess ||
            (*interface)->GetInterfaceProtocol(interface, &interfaceProtocol) != kIOReturnSuccess) {
            LOG(ERROR) << "Unable to get interface class, subclass and protocol";
            goto err_get_interface_class;
    }

    //* check to make sure interface class, subclass and protocol match ADB
    //* avoid opening mass storage endpoints
    if (!is_adb_interface(vendor, product, interfaceClass, interfaceSubClass, interfaceProtocol)) {
        goto err_bad_adb_interface;
    }

    handle.reset(new usb_handle);
    if (handle == nullptr) {
        goto err_bad_adb_interface;
    }

    //* Iterate over the endpoints for this interface and find the first
    //* bulk in/out pipes available.  These will be our read/write pipes.
    for (endpoint = 1; endpoint <= interfaceNumEndpoints; endpoint++) {
        UInt8   transferType;
        UInt16  maxPacketSize;
        UInt8   interval;
        UInt8   number;
        UInt8   direction;

        kr = (*interface)->GetPipeProperties(interface, endpoint, &direction,
                &number, &transferType, &maxPacketSize, &interval);
        if (kr != kIOReturnSuccess) {
            LOG(ERROR) << "FindDeviceInterface - could not get pipe properties: "
                       << std::hex << kr;
            goto err_get_pipe_props;
        }

        if (kUSBBulk != transferType) continue;

        if (kUSBIn == direction) {
            handle->bulkIn = endpoint;
            if (!ClearPipeStallBothEnds(interface, handle->bulkIn)) goto err_get_pipe_props;
        }

        if (kUSBOut == direction) {
            handle->bulkOut = endpoint;
            if (!ClearPipeStallBothEnds(interface, handle->bulkOut)) goto err_get_pipe_props;
        }

        handle->zero_mask = maxPacketSize - 1;
    }

    handle->interface = interface;
    return handle;

err_get_pipe_props:
err_bad_adb_interface:
err_get_interface_class:
err_get_num_ep:
    (*interface)->USBInterfaceClose(interface);
    return nullptr;
}

std::mutex& operate_device_lock = *new std::mutex();

static void RunLoopThread(void* unused) {
    adb_thread_setname("RunLoop");

    VLOG(USB) << "RunLoopThread started";
    while (true) {
        {
            std::lock_guard<std::mutex> lock_guard(operate_device_lock);
            FindUSBDevices();
            KickDisconnectedDevices();
        }
        // Signal the parent that we are running
        usb_inited_flag = true;
        adb_sleep_ms(1000);
    }
    VLOG(USB) << "RunLoopThread done";
}

static void usb_cleanup() {
    VLOG(USB) << "usb_cleanup";
    // Wait until usb operations in RunLoopThread finish, and prevent further operations.
    operate_device_lock.lock();
    close_usb_devices();
}

void usb_init() {
    static bool initialized = false;
    if (!initialized) {
        atexit(usb_cleanup);

        usb_inited_flag = false;

        if (!adb_thread_create(RunLoopThread, nullptr)) {
            fatal_errno("cannot create RunLoop thread");
        }

        // Wait for initialization to finish
        while (!usb_inited_flag) {
            adb_sleep_ms(100);
        }

        initialized = true;
    }
}

int usb_write(usb_handle *handle, const void *buf, int len)
{
    IOReturn    result;

    if (!len)
        return 0;

    if (!handle || handle->dead)
        return -1;

    if (NULL == handle->interface) {
        LOG(ERROR) << "usb_write interface was null";
        return -1;
    }

    if (0 == handle->bulkOut) {
        LOG(ERROR) << "bulkOut endpoint not assigned";
        return -1;
    }

    result =
        (*handle->interface)->WritePipe(handle->interface, handle->bulkOut, (void *)buf, len);

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

    LOG(ERROR) << "usb_write failed with status: " << std::hex << result;
    return -1;
}

int usb_read(usb_handle *handle, void *buf, int len)
{
    IOReturn result;
    UInt32  numBytes = len;

    if (!len) {
        return 0;
    }

    if (!handle || handle->dead) {
        return -1;
    }

    if (NULL == handle->interface) {
        LOG(ERROR) << "usb_read interface was null";
        return -1;
    }

    if (0 == handle->bulkIn) {
        LOG(ERROR) << "bulkIn endpoint not assigned";
        return -1;
    }

    result = (*handle->interface)->ReadPipe(handle->interface, handle->bulkIn, buf, &numBytes);

    if (kIOUSBPipeStalled == result) {
        LOG(ERROR) << "Pipe stalled, clearing stall.\n";
        (*handle->interface)->ClearPipeStall(handle->interface, handle->bulkIn);
        result = (*handle->interface)->ReadPipe(handle->interface, handle->bulkIn, buf, &numBytes);
    }

    if (kIOReturnSuccess == result)
        return 0;
    else {
        LOG(ERROR) << "usb_read failed with status: " << std::hex << result;
    }

    return -1;
}

int usb_close(usb_handle *handle)
{
    std::lock_guard<std::mutex> lock(g_usb_handles_mutex);
    for (auto it = g_usb_handles.begin(); it != g_usb_handles.end(); ++it) {
        if ((*it).get() == handle) {
            g_usb_handles.erase(it);
            break;
        }
    }
    return 0;
}

static void usb_kick_locked(usb_handle *handle)
{
    LOG(INFO) << "Kicking handle";
    /* release the interface */
    if (!handle)
        return;

    if (!handle->dead)
    {
        handle->dead = true;
        (*handle->interface)->USBInterfaceClose(handle->interface);
        (*handle->interface)->Release(handle->interface);
    }
}

void usb_kick(usb_handle *handle) {
    // Use the lock to avoid multiple thread kicking the device at the same time.
    std::lock_guard<std::mutex> lock_guard(g_usb_handles_mutex);
    usb_kick_locked(handle);
}

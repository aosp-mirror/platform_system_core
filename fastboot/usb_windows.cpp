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

#include <windows.h>
#include <winerror.h>
#include <errno.h>
#include <usb100.h>
#include <adb_api.h>
#include <stdio.h>
#include <stdlib.h>

#include <memory>
#include <string>

#include "usb.h"

//#define TRACE_USB 1
#if TRACE_USB
#define DBG(x...) fprintf(stderr, x)
#else
#define DBG(x...)
#endif

#define MAX_USBFS_BULK_SIZE (1024 * 1024)

/** Structure usb_handle describes our connection to the usb device via
  AdbWinApi.dll. This structure is returned from usb_open() routine and
  is expected in each subsequent call that is accessing the device.
*/
struct usb_handle {
    /// Handle to USB interface
    ADBAPIHANDLE  adb_interface;

    /// Handle to USB read pipe (endpoint)
    ADBAPIHANDLE  adb_read_pipe;

    /// Handle to USB write pipe (endpoint)
    ADBAPIHANDLE  adb_write_pipe;

    /// Interface name
    std::string interface_name;
};

class WindowsUsbTransport : public UsbTransport {
  public:
    WindowsUsbTransport(std::unique_ptr<usb_handle> handle) : handle_(std::move(handle)) {}
    ~WindowsUsbTransport() override;

    ssize_t Read(void* data, size_t len) override;
    ssize_t Write(const void* data, size_t len) override;
    int Close() override;
    int Reset() override;

  private:
    std::unique_ptr<usb_handle> handle_;

    DISALLOW_COPY_AND_ASSIGN(WindowsUsbTransport);
};

/// Class ID assigned to the device by androidusb.sys
static const GUID usb_class_id = ANDROID_USB_CLASS_ID;

/// Checks if interface (device) matches certain criteria
int recognized_device(usb_handle* handle, ifc_match_func callback);

/// Opens usb interface (device) by interface (device) name.
std::unique_ptr<usb_handle> do_usb_open(const wchar_t* interface_name);

/// Cleans up opened usb handle
void usb_cleanup_handle(usb_handle* handle);

/// Cleans up (but don't close) opened usb handle
void usb_kick(usb_handle* handle);


std::unique_ptr<usb_handle> do_usb_open(const wchar_t* interface_name) {
    // Allocate our handle
    std::unique_ptr<usb_handle> ret(new usb_handle);

    // Create interface.
    ret->adb_interface = AdbCreateInterfaceByName(interface_name);

    if (nullptr == ret->adb_interface) {
        errno = GetLastError();
        DBG("failed to open interface %S\n", interface_name);
        return nullptr;
    }

    // Open read pipe (endpoint)
    ret->adb_read_pipe =
        AdbOpenDefaultBulkReadEndpoint(ret->adb_interface,
                                   AdbOpenAccessTypeReadWrite,
                                   AdbOpenSharingModeReadWrite);
    if (nullptr != ret->adb_read_pipe) {
        // Open write pipe (endpoint)
        ret->adb_write_pipe =
            AdbOpenDefaultBulkWriteEndpoint(ret->adb_interface,
                                      AdbOpenAccessTypeReadWrite,
                                      AdbOpenSharingModeReadWrite);
        if (nullptr != ret->adb_write_pipe) {
            // Save interface name
            unsigned long name_len = 0;

            // First get expected name length
            AdbGetInterfaceName(ret->adb_interface,
                          nullptr,
                          &name_len,
                          true);
            if (0 != name_len) {
                // Now save the name
                ret->interface_name.resize(name_len);
                if (AdbGetInterfaceName(ret->adb_interface,
                              &ret->interface_name[0],
                              &name_len,
                              true)) {
                    // We're done at this point
                    return ret;
                }
            }
        }
    }

    // Something went wrong.
    errno = GetLastError();
    usb_cleanup_handle(ret.get());
    SetLastError(errno);

    return nullptr;
}

ssize_t WindowsUsbTransport::Write(const void* data, size_t len) {
    unsigned long time_out = 5000;
    unsigned long written = 0;
    unsigned count = 0;
    int ret;

    DBG("usb_write %zu\n", len);
    if (nullptr != handle_) {
        // Perform write
        while(len > 0) {
            int xfer = (len > MAX_USBFS_BULK_SIZE) ? MAX_USBFS_BULK_SIZE : len;
            ret = AdbWriteEndpointSync(handle_->adb_write_pipe, const_cast<void*>(data), xfer,
                                       &written, time_out);
            errno = GetLastError();
            DBG("AdbWriteEndpointSync returned %d, errno: %d\n", ret, errno);
            if (ret == 0) {
                // assume ERROR_INVALID_HANDLE indicates we are disconnected
                if (errno == ERROR_INVALID_HANDLE)
                usb_kick(handle_.get());
                return -1;
            }

            count += written;
            len -= written;
            data = (const char *)data + written;

            if (len == 0)
                return count;
        }
    } else {
        DBG("usb_write NULL handle\n");
        SetLastError(ERROR_INVALID_HANDLE);
    }

    DBG("usb_write failed: %d\n", errno);

    return -1;
}

ssize_t WindowsUsbTransport::Read(void* data, size_t len) {
    unsigned long time_out = 0;
    unsigned long read = 0;
    size_t count = 0;
    int ret;

    DBG("usb_read %zu\n", len);
    if (nullptr != handle_) {
        while (len > 0) {
            size_t xfer = (len > MAX_USBFS_BULK_SIZE) ? MAX_USBFS_BULK_SIZE : len;

            ret = AdbReadEndpointSync(handle_->adb_read_pipe, data, xfer, &read, time_out);
            errno = GetLastError();
            DBG("usb_read got: %lu, expected: %zu, errno: %d\n", read, xfer, errno);
            if (ret == 0) {
                // assume ERROR_INVALID_HANDLE indicates we are disconnected
                if (errno == ERROR_INVALID_HANDLE)
                    usb_kick(handle_.get());
                break;
            }
            count += read;
            len -= read;
            data = (char*)data + read;

            if (xfer != read || len == 0) return count;
        }
    } else {
        DBG("usb_read NULL handle\n");
        SetLastError(ERROR_INVALID_HANDLE);
    }

    DBG("usb_read failed: %d\n", errno);

    return -1;
}

void usb_cleanup_handle(usb_handle* handle) {
    if (NULL != handle) {
        if (NULL != handle->adb_write_pipe)
            AdbCloseHandle(handle->adb_write_pipe);
        if (NULL != handle->adb_read_pipe)
            AdbCloseHandle(handle->adb_read_pipe);
        if (NULL != handle->adb_interface)
            AdbCloseHandle(handle->adb_interface);

        handle->interface_name.clear();
        handle->adb_write_pipe = NULL;
        handle->adb_read_pipe = NULL;
        handle->adb_interface = NULL;
    }
}

void usb_kick(usb_handle* handle) {
    if (NULL != handle) {
        usb_cleanup_handle(handle);
    } else {
        SetLastError(ERROR_INVALID_HANDLE);
        errno = ERROR_INVALID_HANDLE;
    }
}

WindowsUsbTransport::~WindowsUsbTransport() {
    Close();
}

int WindowsUsbTransport::Close() {
    DBG("usb_close\n");

    if (nullptr != handle_) {
        // Cleanup handle
        usb_cleanup_handle(handle_.get());
        handle_.reset();
    }

    return 0;
}

int WindowsUsbTransport::Reset() {
    DBG("usb_reset currently unsupported\n\n");
    // TODO, this is a bit complicated since it is using ADB
    return -1;
}

int recognized_device(usb_handle* handle, ifc_match_func callback) {
    struct usb_ifc_info info;
    USB_DEVICE_DESCRIPTOR device_desc;
    USB_INTERFACE_DESCRIPTOR interf_desc;

    if (NULL == handle)
        return 0;

    // Check vendor and product id first
    if (!AdbGetUsbDeviceDescriptor(handle->adb_interface, &device_desc)) {
        DBG("skipping device %x:%x\n", device_desc.idVendor, device_desc.idProduct);
        return 0;
    }

    // Then check interface properties
    if (!AdbGetUsbInterfaceDescriptor(handle->adb_interface, &interf_desc)) {
        DBG("skipping device %x:%x, failed to find interface\n", device_desc.idVendor,
            device_desc.idProduct);
        return 0;
    }

    // Must have two endpoints
    if (2 != interf_desc.bNumEndpoints) {
        DBG("skipping device %x:%x, incorrect number of endpoints\n", device_desc.idVendor,
            device_desc.idProduct);
        return 0;
    }

    info.dev_vendor = device_desc.idVendor;
    info.dev_product = device_desc.idProduct;
    info.dev_class = device_desc.bDeviceClass;
    info.dev_subclass = device_desc.bDeviceSubClass;
    info.dev_protocol = device_desc.bDeviceProtocol;
    info.ifc_class = interf_desc.bInterfaceClass;
    info.ifc_subclass = interf_desc.bInterfaceSubClass;
    info.ifc_protocol = interf_desc.bInterfaceProtocol;
    info.writable = 1;

    // read serial number (if there is one)
    unsigned long serial_number_len = sizeof(info.serial_number);
    if (!AdbGetSerialNumber(handle->adb_interface, info.serial_number,
                    &serial_number_len, true)) {
        info.serial_number[0] = 0;
    }
    info.interface[0] = 0;

    info.device_path[0] = 0;

    if (callback(&info) == 0) {
        DBG("skipping device %x:%x, not selected by callback\n", device_desc.idVendor,
            device_desc.idProduct);
        return 1;
    }

    DBG("found device %x:%x (%s)\n", device_desc.idVendor, device_desc.idProduct,
        info.serial_number);
    return 0;
}

static std::unique_ptr<usb_handle> find_usb_device(ifc_match_func callback) {
    std::unique_ptr<usb_handle> handle;
    char entry_buffer[2048];
    char interf_name[2048];
    AdbInterfaceInfo* next_interface = (AdbInterfaceInfo*)(&entry_buffer[0]);
    unsigned long entry_buffer_size = sizeof(entry_buffer);
    char* copy_name;

    // Enumerate all present and active interfaces.
    ADBAPIHANDLE enum_handle =
        AdbEnumInterfaces(usb_class_id, true, true, true);

    if (NULL == enum_handle)
        return NULL;

    while (AdbNextInterface(enum_handle, next_interface, &entry_buffer_size)) {
        // TODO(vchtchetkine): FIXME - temp hack converting wchar_t into char.
        // It would be better to change AdbNextInterface so it will return
        // interface name as single char string.
        const wchar_t* wchar_name = next_interface->device_name;
        for(copy_name = interf_name;
                L'\0' != *wchar_name;
                wchar_name++, copy_name++) {
            *copy_name = (char)(*wchar_name);
        }
        *copy_name = '\0';

        DBG("attempting to open interface %S\n", next_interface->device_name);
        handle = do_usb_open(next_interface->device_name);
        if (NULL != handle) {
            // Lets see if this interface (device) belongs to us
            if (recognized_device(handle.get(), callback)) {
                // found it!
                break;
            } else {
                usb_cleanup_handle(handle.get());
                handle.reset();
            }
        }

        entry_buffer_size = sizeof(entry_buffer);
    }

    AdbCloseHandle(enum_handle);
    return handle;
}

std::unique_ptr<UsbTransport> usb_open(ifc_match_func callback, uint32_t) {
    std::unique_ptr<UsbTransport> result;
    std::unique_ptr<usb_handle> handle = find_usb_device(callback);

    if (handle) {
        result = std::make_unique<WindowsUsbTransport>(std::move(handle));
    }

    return result;
}

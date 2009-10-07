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

#include "usb.h"

//#define TRACE_USB 1
#if TRACE_USB
#define DBG(x...) fprintf(stderr, x)
#else
#define DBG(x...)
#endif


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
    char*         interface_name;
};

/// Class ID assigned to the device by androidusb.sys
static const GUID usb_class_id = ANDROID_USB_CLASS_ID;


/// Checks if interface (device) matches certain criteria
int recognized_device(usb_handle* handle, ifc_match_func callback);

/// Opens usb interface (device) by interface (device) name.
usb_handle* do_usb_open(const wchar_t* interface_name);

/// Writes data to the opened usb handle
int usb_write(usb_handle* handle, const void* data, int len);

/// Reads data using the opened usb handle
int usb_read(usb_handle *handle, void* data, int len);

/// Cleans up opened usb handle
void usb_cleanup_handle(usb_handle* handle);

/// Cleans up (but don't close) opened usb handle
void usb_kick(usb_handle* handle);

/// Closes opened usb handle
int usb_close(usb_handle* handle);


usb_handle* do_usb_open(const wchar_t* interface_name) {
    // Allocate our handle
    usb_handle* ret = (usb_handle*)malloc(sizeof(usb_handle));
    if (NULL == ret)
        return NULL;

    // Create interface.
    ret->adb_interface = AdbCreateInterfaceByName(interface_name);

    if (NULL == ret->adb_interface) {
        free(ret);
        errno = GetLastError();
        return NULL;
    }

    // Open read pipe (endpoint)
    ret->adb_read_pipe =
        AdbOpenDefaultBulkReadEndpoint(ret->adb_interface,
                                   AdbOpenAccessTypeReadWrite,
                                   AdbOpenSharingModeReadWrite);
    if (NULL != ret->adb_read_pipe) {
        // Open write pipe (endpoint)
        ret->adb_write_pipe =
            AdbOpenDefaultBulkWriteEndpoint(ret->adb_interface,
                                      AdbOpenAccessTypeReadWrite,
                                      AdbOpenSharingModeReadWrite);
        if (NULL != ret->adb_write_pipe) {
            // Save interface name
            unsigned long name_len = 0;

            // First get expected name length
            AdbGetInterfaceName(ret->adb_interface,
                          NULL,
                          &name_len,
                          true);
            if (0 != name_len) {
                ret->interface_name = (char*)malloc(name_len);

                if (NULL != ret->interface_name) {
                    // Now save the name
                    if (AdbGetInterfaceName(ret->adb_interface,
                                  ret->interface_name,
                                  &name_len,
                                  true)) {
                        // We're done at this point
                        return ret;
                    }
                } else {
                    SetLastError(ERROR_OUTOFMEMORY);
                }
            }
        }
    }

    // Something went wrong.
    errno = GetLastError();
    usb_cleanup_handle(ret);
    free(ret);
    SetLastError(errno);

    return NULL;
}

int usb_write(usb_handle* handle, const void* data, int len) {
    unsigned long time_out = 500 + len * 8;
    unsigned long written = 0;
    unsigned count = 0;
    int ret;

    DBG("usb_write %d\n", len);
    if (NULL != handle) {
        // Perform write
        while(len > 0) {
            int xfer = (len > 4096) ? 4096 : len;
            ret = AdbWriteEndpointSync(handle->adb_write_pipe,
                                   (void*)data,
                                   (unsigned long)xfer,
                                   &written,
                                   time_out);
            errno = GetLastError();
            DBG("AdbWriteEndpointSync returned %d, errno: %d\n", ret, errno);
            if (ret == 0) {
                // assume ERROR_INVALID_HANDLE indicates we are disconnected
                if (errno == ERROR_INVALID_HANDLE)
                usb_kick(handle);
                return -1;
            }

            count += written;
            len -= written;
            data += written;

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

int usb_read(usb_handle *handle, void* data, int len) {
    unsigned long time_out = 500 + len * 8;
    unsigned long read = 0;
    int ret;

    DBG("usb_read %d\n", len);
    if (NULL != handle) {
        while (1) {
            int xfer = (len > 4096) ? 4096 : len;

	        ret = AdbReadEndpointSync(handle->adb_read_pipe,
	                              (void*)data,
	                              (unsigned long)xfer,
	                              &read,
	                              time_out);
            errno = GetLastError();
            DBG("usb_read got: %ld, expected: %d, errno: %d\n", read, xfer, errno);
            if (ret) {
                return read;
            } else if (errno != ERROR_SEM_TIMEOUT) {
                // assume ERROR_INVALID_HANDLE indicates we are disconnected
                if (errno == ERROR_INVALID_HANDLE)
                    usb_kick(handle);
                break;
            }
            // else we timed out - try again
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
        if (NULL != handle->interface_name)
            free(handle->interface_name);
        if (NULL != handle->adb_write_pipe)
            AdbCloseHandle(handle->adb_write_pipe);
        if (NULL != handle->adb_read_pipe)
            AdbCloseHandle(handle->adb_read_pipe);
        if (NULL != handle->adb_interface)
            AdbCloseHandle(handle->adb_interface);

        handle->interface_name = NULL;
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

int usb_close(usb_handle* handle) {
    DBG("usb_close\n");

    if (NULL != handle) {
        // Cleanup handle
        usb_cleanup_handle(handle);
        free(handle);
    }

    return 0;
}

int recognized_device(usb_handle* handle, ifc_match_func callback) {
    struct usb_ifc_info info;
    USB_DEVICE_DESCRIPTOR device_desc;
    USB_INTERFACE_DESCRIPTOR interf_desc;

    if (NULL == handle)
        return 0;

    // Check vendor and product id first
    if (!AdbGetUsbDeviceDescriptor(handle->adb_interface,
                                 &device_desc)) {
        return 0;
    }

    // Then check interface properties
    if (!AdbGetUsbInterfaceDescriptor(handle->adb_interface,
                                    &interf_desc)) {
        return 0;
    }

    // Must have two endpoints
    if (2 != interf_desc.bNumEndpoints) {
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

    if (callback(&info) == 0) {
        return 1;
    }

    return 0;
}

static usb_handle *find_usb_device(ifc_match_func callback) {
	usb_handle* handle = NULL;
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

        handle = do_usb_open(next_interface->device_name);
        if (NULL != handle) {
            // Lets see if this interface (device) belongs to us
            if (recognized_device(handle, callback)) {
                // found it!
                break;
            } else {
                usb_cleanup_handle(handle);
                free(handle);
                handle = NULL;
            }
        }

        entry_buffer_size = sizeof(entry_buffer);
    }

    AdbCloseHandle(enum_handle);
    return handle;
}

usb_handle *usb_open(ifc_match_func callback)
{
    return find_usb_device(callback);
}

// called from fastboot.c
void sleep(int seconds)
{
    Sleep(seconds * 1000);
}

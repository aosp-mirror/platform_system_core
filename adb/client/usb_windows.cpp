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

// clang-format off
#include <winsock2.h>  // winsock.h *must* be included before windows.h.
#include <windows.h>
// clang-format on
#include <usb100.h>
#include <winerror.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <algorithm>
#include <mutex>
#include <thread>

#include <adb_api.h>

#include <android-base/errors.h>

#include "adb.h"
#include "sysdeps/chrono.h"
#include "transport.h"

namespace native {

/** Structure usb_handle describes our connection to the usb device via
  AdbWinApi.dll. This structure is returned from usb_open() routine and
  is expected in each subsequent call that is accessing the device.

  Most members are protected by usb_lock, except for adb_{read,write}_pipe which
  rely on AdbWinApi.dll's handle validation and AdbCloseHandle(endpoint)'s
  ability to break a thread out of pipe IO.
*/
struct usb_handle : public ::usb_handle {
    /// Handle to USB interface
    ADBAPIHANDLE adb_interface;

    /// Handle to USB read pipe (endpoint)
    ADBAPIHANDLE adb_read_pipe;

    /// Handle to USB write pipe (endpoint)
    ADBAPIHANDLE adb_write_pipe;

    /// Interface name
    wchar_t* interface_name;

    /// Maximum packet size.
    unsigned max_packet_size;

    /// Mask for determining when to use zero length packets
    unsigned zero_mask;
};

/// Class ID assigned to the device by androidusb.sys
static const GUID usb_class_id = ANDROID_USB_CLASS_ID;

/// List of opened usb handles
static std::vector<usb_handle*>& handle_list = *new std::vector<usb_handle*>();

/// Locker for the list of opened usb handles
static std::mutex& usb_lock = *new std::mutex();

/// Checks if there is opened usb handle in handle_list for this device.
int known_device(const wchar_t* dev_name);

/// Checks if there is opened usb handle in handle_list for this device.
/// usb_lock mutex must be held before calling this routine.
int known_device_locked(const wchar_t* dev_name);

/// Registers opened usb handle (adds it to handle_list).
int register_new_device(usb_handle* handle);

/// Checks if interface (device) matches certain criteria
int recognized_device(usb_handle* handle);

/// Enumerates present and available interfaces (devices), opens new ones and
/// registers usb transport for them.
void find_devices();

/// Kicks all USB devices
static void kick_devices();

/// Entry point for thread that polls (every second) for new usb interfaces.
/// This routine calls find_devices in infinite loop.
static void device_poll_thread();

/// Initializes this module
void usb_init();

/// Opens usb interface (device) by interface (device) name.
usb_handle* do_usb_open(const wchar_t* interface_name);

/// Writes data to the opened usb handle
int usb_write(usb_handle* handle, const void* data, int len);

/// Reads data using the opened usb handle
int usb_read(usb_handle* handle, void* data, int len);

/// Cleans up opened usb handle
void usb_cleanup_handle(usb_handle* handle);

/// Cleans up (but don't close) opened usb handle
void usb_kick(usb_handle* handle);

/// Closes opened usb handle
int usb_close(usb_handle* handle);

int known_device_locked(const wchar_t* dev_name) {
    if (nullptr != dev_name) {
        // Iterate through the list looking for the name match.
        for (usb_handle* usb : handle_list) {
            // In Windows names are not case sensetive!
            if ((nullptr != usb->interface_name) && (0 == wcsicmp(usb->interface_name, dev_name))) {
                return 1;
            }
        }
    }

    return 0;
}

int known_device(const wchar_t* dev_name) {
    int ret = 0;

    if (nullptr != dev_name) {
        std::lock_guard<std::mutex> lock(usb_lock);
        ret = known_device_locked(dev_name);
    }

    return ret;
}

int register_new_device(usb_handle* handle) {
    if (nullptr == handle) return 0;

    std::lock_guard<std::mutex> lock(usb_lock);

    // Check if device is already in the list
    if (known_device_locked(handle->interface_name)) {
        return 0;
    }

    // Not in the list. Add this handle to the list.
    handle_list.push_back(handle);

    return 1;
}

void device_poll_thread() {
    adb_thread_setname("Device Poll");
    D("Created device thread");

    while (true) {
        find_devices();
        std::this_thread::sleep_for(1s);
    }
}

static LRESULT CALLBACK _power_window_proc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_POWERBROADCAST:
            switch (wParam) {
                case PBT_APMRESUMEAUTOMATIC:
                    // Resuming from sleep or hibernation, so kick all existing USB devices
                    // and then allow the device_poll_thread to redetect USB devices from
                    // scratch. If we don't do this, existing USB devices will never respond
                    // to us because they'll be waiting for the connect/auth handshake.
                    D("Received (WM_POWERBROADCAST, PBT_APMRESUMEAUTOMATIC) notification, "
                      "so kicking all USB devices\n");
                    kick_devices();
                    return TRUE;
            }
    }
    return DefWindowProcW(hwnd, uMsg, wParam, lParam);
}

static void _power_notification_thread() {
    // This uses a thread with its own window message pump to get power
    // notifications. If adb runs from a non-interactive service account, this
    // might not work (not sure). If that happens to not work, we could use
    // heavyweight WMI APIs to get power notifications. But for the common case
    // of a developer's interactive session, a window message pump is more
    // appropriate.
    D("Created power notification thread");
    adb_thread_setname("Power Notifier");

    // Window class names are process specific.
    static const WCHAR kPowerNotificationWindowClassName[] = L"PowerNotificationWindow";

    // Get the HINSTANCE corresponding to the module that _power_window_proc
    // is in (the main module).
    const HINSTANCE instance = GetModuleHandleW(nullptr);
    if (!instance) {
        // This is such a common API call that this should never fail.
        fatal("GetModuleHandleW failed: %s",
              android::base::SystemErrorCodeToString(GetLastError()).c_str());
    }

    WNDCLASSEXW wndclass;
    memset(&wndclass, 0, sizeof(wndclass));
    wndclass.cbSize = sizeof(wndclass);
    wndclass.lpfnWndProc = _power_window_proc;
    wndclass.hInstance = instance;
    wndclass.lpszClassName = kPowerNotificationWindowClassName;
    if (!RegisterClassExW(&wndclass)) {
        fatal("RegisterClassExW failed: %s",
              android::base::SystemErrorCodeToString(GetLastError()).c_str());
    }

    if (!CreateWindowExW(WS_EX_NOACTIVATE, kPowerNotificationWindowClassName,
                         L"ADB Power Notification Window", WS_POPUP, 0, 0, 0, 0, nullptr, nullptr,
                         instance, nullptr)) {
        fatal("CreateWindowExW failed: %s",
              android::base::SystemErrorCodeToString(GetLastError()).c_str());
    }

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    // GetMessageW() will return false if a quit message is posted. We don't
    // do that, but it might be possible for that to occur when logging off or
    // shutting down. Not a big deal since the whole process will be going away
    // soon anyway.
    D("Power notification thread exiting");
}

void usb_init() {
    std::thread(device_poll_thread).detach();
    std::thread(_power_notification_thread).detach();
}

void usb_cleanup() {}

usb_handle* do_usb_open(const wchar_t* interface_name) {
    unsigned long name_len = 0;

    // Allocate our handle
    usb_handle* ret = (usb_handle*)calloc(1, sizeof(usb_handle));
    if (nullptr == ret) {
        D("Could not allocate %u bytes for usb_handle: %s", sizeof(usb_handle), strerror(errno));
        goto fail;
    }

    // Create interface.
    ret->adb_interface = AdbCreateInterfaceByName(interface_name);
    if (nullptr == ret->adb_interface) {
        D("AdbCreateInterfaceByName failed: %s",
          android::base::SystemErrorCodeToString(GetLastError()).c_str());
        goto fail;
    }

    // Open read pipe (endpoint)
    ret->adb_read_pipe = AdbOpenDefaultBulkReadEndpoint(
        ret->adb_interface, AdbOpenAccessTypeReadWrite, AdbOpenSharingModeReadWrite);
    if (nullptr == ret->adb_read_pipe) {
        D("AdbOpenDefaultBulkReadEndpoint failed: %s",
          android::base::SystemErrorCodeToString(GetLastError()).c_str());
        goto fail;
    }

    // Open write pipe (endpoint)
    ret->adb_write_pipe = AdbOpenDefaultBulkWriteEndpoint(
        ret->adb_interface, AdbOpenAccessTypeReadWrite, AdbOpenSharingModeReadWrite);
    if (nullptr == ret->adb_write_pipe) {
        D("AdbOpenDefaultBulkWriteEndpoint failed: %s",
          android::base::SystemErrorCodeToString(GetLastError()).c_str());
        goto fail;
    }

    // Save interface name
    // First get expected name length
    AdbGetInterfaceName(ret->adb_interface, nullptr, &name_len, false);
    if (0 == name_len) {
        D("AdbGetInterfaceName returned name length of zero: %s",
          android::base::SystemErrorCodeToString(GetLastError()).c_str());
        goto fail;
    }

    ret->interface_name = (wchar_t*)malloc(name_len * sizeof(ret->interface_name[0]));
    if (nullptr == ret->interface_name) {
        D("Could not allocate %lu characters for interface_name: %s", name_len, strerror(errno));
        goto fail;
    }

    // Now save the name
    if (!AdbGetInterfaceName(ret->adb_interface, ret->interface_name, &name_len, false)) {
        D("AdbGetInterfaceName failed: %s",
          android::base::SystemErrorCodeToString(GetLastError()).c_str());
        goto fail;
    }

    // We're done at this point
    return ret;

fail:
    if (nullptr != ret) {
        usb_cleanup_handle(ret);
        free(ret);
    }

    return nullptr;
}

int usb_write(usb_handle* handle, const void* data, int len) {
    unsigned long time_out = 5000;
    unsigned long written = 0;
    int err = 0;

    D("usb_write %d", len);
    if (nullptr == handle) {
        D("usb_write was passed NULL handle");
        err = EINVAL;
        goto fail;
    }

    // Perform write
    if (!AdbWriteEndpointSync(handle->adb_write_pipe, (void*)data, (unsigned long)len, &written,
                              time_out)) {
        D("AdbWriteEndpointSync failed: %s",
          android::base::SystemErrorCodeToString(GetLastError()).c_str());
        err = EIO;
        goto fail;
    }

    // Make sure that we've written what we were asked to write
    D("usb_write got: %ld, expected: %d", written, len);
    if (written != (unsigned long)len) {
        // If this occurs, this code should be changed to repeatedly call
        // AdbWriteEndpointSync() until all bytes are written.
        D("AdbWriteEndpointSync was supposed to write %d, but only wrote %ld", len, written);
        err = EIO;
        goto fail;
    }

    if (handle->zero_mask && (len & handle->zero_mask) == 0) {
        // Send a zero length packet
        unsigned long dummy;
        if (!AdbWriteEndpointSync(handle->adb_write_pipe, (void*)data, 0, &dummy, time_out)) {
            D("AdbWriteEndpointSync of zero length packet failed: %s",
              android::base::SystemErrorCodeToString(GetLastError()).c_str());
            err = EIO;
            goto fail;
        }
    }

    return written;

fail:
    // Any failure should cause us to kick the device instead of leaving it a
    // zombie state with potential to hang.
    if (nullptr != handle) {
        D("Kicking device due to error in usb_write");
        usb_kick(handle);
    }

    D("usb_write failed");
    errno = err;
    return -1;
}

int usb_read(usb_handle* handle, void* data, int len) {
    unsigned long time_out = 0;
    unsigned long read = 0;
    int err = 0;
    int orig_len = len;

    D("usb_read %d", len);
    if (nullptr == handle) {
        D("usb_read was passed NULL handle");
        err = EINVAL;
        goto fail;
    }

    while (len == orig_len) {
        if (!AdbReadEndpointSync(handle->adb_read_pipe, data, len, &read, time_out)) {
            D("AdbReadEndpointSync failed: %s",
              android::base::SystemErrorCodeToString(GetLastError()).c_str());
            err = EIO;
            goto fail;
        }
        D("usb_read got: %ld, expected: %d", read, len);

        data = (char*)data + read;
        len -= read;
    }

    return orig_len - len;

fail:
    // Any failure should cause us to kick the device instead of leaving it a
    // zombie state with potential to hang.
    if (nullptr != handle) {
        D("Kicking device due to error in usb_read");
        usb_kick(handle);
    }

    D("usb_read failed");
    errno = err;
    return -1;
}

// Wrapper around AdbCloseHandle() that logs diagnostics.
static void _adb_close_handle(ADBAPIHANDLE adb_handle) {
    if (!AdbCloseHandle(adb_handle)) {
        D("AdbCloseHandle(%p) failed: %s", adb_handle,
          android::base::SystemErrorCodeToString(GetLastError()).c_str());
    }
}

void usb_cleanup_handle(usb_handle* handle) {
    D("usb_cleanup_handle");
    if (nullptr != handle) {
        if (nullptr != handle->interface_name) free(handle->interface_name);
        // AdbCloseHandle(pipe) will break any threads out of pending IO calls and
        // wait until the pipe no longer uses the interface. Then we can
        // AdbCloseHandle() the interface.
        if (nullptr != handle->adb_write_pipe) _adb_close_handle(handle->adb_write_pipe);
        if (nullptr != handle->adb_read_pipe) _adb_close_handle(handle->adb_read_pipe);
        if (nullptr != handle->adb_interface) _adb_close_handle(handle->adb_interface);

        handle->interface_name = nullptr;
        handle->adb_write_pipe = nullptr;
        handle->adb_read_pipe = nullptr;
        handle->adb_interface = nullptr;
    }
}

static void usb_kick_locked(usb_handle* handle) {
    // The reason the lock must be acquired before calling this function is in
    // case multiple threads are trying to kick the same device at the same time.
    usb_cleanup_handle(handle);
}

void usb_kick(usb_handle* handle) {
    D("usb_kick");
    if (nullptr != handle) {
        std::lock_guard<std::mutex> lock(usb_lock);
        usb_kick_locked(handle);
    } else {
        errno = EINVAL;
    }
}

int usb_close(usb_handle* handle) {
    D("usb_close");

    if (nullptr != handle) {
        // Remove handle from the list
        {
            std::lock_guard<std::mutex> lock(usb_lock);
            handle_list.erase(std::remove(handle_list.begin(), handle_list.end(), handle),
                              handle_list.end());
        }

        // Cleanup handle
        usb_cleanup_handle(handle);
        free(handle);
    }

    return 0;
}

size_t usb_get_max_packet_size(usb_handle* handle) {
    return handle->max_packet_size;
}

int recognized_device(usb_handle* handle) {
    if (nullptr == handle) return 0;

    // Check vendor and product id first
    USB_DEVICE_DESCRIPTOR device_desc;

    if (!AdbGetUsbDeviceDescriptor(handle->adb_interface, &device_desc)) {
        D("AdbGetUsbDeviceDescriptor failed: %s",
          android::base::SystemErrorCodeToString(GetLastError()).c_str());
        return 0;
    }

    // Then check interface properties
    USB_INTERFACE_DESCRIPTOR interf_desc;

    if (!AdbGetUsbInterfaceDescriptor(handle->adb_interface, &interf_desc)) {
        D("AdbGetUsbInterfaceDescriptor failed: %s",
          android::base::SystemErrorCodeToString(GetLastError()).c_str());
        return 0;
    }

    // Must have two endpoints
    if (2 != interf_desc.bNumEndpoints) {
        return 0;
    }

    if (!is_adb_interface(interf_desc.bInterfaceClass, interf_desc.bInterfaceSubClass,
                          interf_desc.bInterfaceProtocol)) {
        return 0;
    }

    AdbEndpointInformation endpoint_info;
    // assuming zero is a valid bulk endpoint ID
    if (AdbGetEndpointInformation(handle->adb_interface, 0, &endpoint_info)) {
        handle->max_packet_size = endpoint_info.max_packet_size;
        handle->zero_mask = endpoint_info.max_packet_size - 1;
        D("device zero_mask: 0x%x", handle->zero_mask);
    } else {
        D("AdbGetEndpointInformation failed: %s",
          android::base::SystemErrorCodeToString(GetLastError()).c_str());
    }

    return 1;
}

void find_devices() {
    usb_handle* handle = nullptr;
    char entry_buffer[2048];
    AdbInterfaceInfo* next_interface = (AdbInterfaceInfo*)(&entry_buffer[0]);
    unsigned long entry_buffer_size = sizeof(entry_buffer);

    // Enumerate all present and active interfaces.
    ADBAPIHANDLE enum_handle = AdbEnumInterfaces(usb_class_id, true, true, true);

    if (nullptr == enum_handle) {
        D("AdbEnumInterfaces failed: %s",
          android::base::SystemErrorCodeToString(GetLastError()).c_str());
        return;
    }

    while (AdbNextInterface(enum_handle, next_interface, &entry_buffer_size)) {
        // Lets see if we already have this device in the list
        if (!known_device(next_interface->device_name)) {
            // This seems to be a new device. Open it!
            handle = do_usb_open(next_interface->device_name);
            if (nullptr != handle) {
                // Lets see if this interface (device) belongs to us
                if (recognized_device(handle)) {
                    D("adding a new device %ls", next_interface->device_name);

                    // We don't request a wchar_t string from AdbGetSerialNumber() because of a bug
                    // in adb_winusb_interface.cpp:CopyMemory(buffer, ser_num->bString,
                    // bytes_written) where the last parameter should be (str_len *
                    // sizeof(wchar_t)). The bug reads 2 bytes past the end of a stack buffer in the
                    // best case, and in the unlikely case of a long serial number, it will read 2
                    // bytes past the end of a heap allocation. This doesn't affect the resulting
                    // string, but we should avoid the bad reads in the first place.
                    char serial_number[512];
                    unsigned long serial_number_len = sizeof(serial_number);
                    if (AdbGetSerialNumber(handle->adb_interface, serial_number, &serial_number_len,
                                           true)) {
                        // Lets make sure that we don't duplicate this device
                        if (register_new_device(handle)) {
                            register_usb_transport(handle, serial_number, nullptr, 1);
                        } else {
                            D("register_new_device failed for %ls", next_interface->device_name);
                            usb_cleanup_handle(handle);
                            free(handle);
                        }
                    } else {
                        D("cannot get serial number: %s",
                          android::base::SystemErrorCodeToString(GetLastError()).c_str());
                        usb_cleanup_handle(handle);
                        free(handle);
                    }
                } else {
                    usb_cleanup_handle(handle);
                    free(handle);
                }
            }
        }

        entry_buffer_size = sizeof(entry_buffer);
    }

    if (GetLastError() != ERROR_NO_MORE_ITEMS) {
        // Only ERROR_NO_MORE_ITEMS is expected at the end of enumeration.
        D("AdbNextInterface failed: %s",
          android::base::SystemErrorCodeToString(GetLastError()).c_str());
    }

    _adb_close_handle(enum_handle);
}

static void kick_devices() {
    // Need to acquire lock to safely walk the list which might be modified
    // by another thread.
    std::lock_guard<std::mutex> lock(usb_lock);
    for (usb_handle* usb : handle_list) {
        usb_kick_locked(usb);
    }
}

}  // namespace native

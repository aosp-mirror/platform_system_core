/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include "usb.h"

#include "sysdeps.h"

#include <stdint.h>
#include <stdlib.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>

#include <libusb/libusb.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>

#include "adb.h"
#include "adb_utils.h"
#include "transport.h"
#include "usb.h"

using android::base::StringPrintf;

// RAII wrappers for libusb.
struct ConfigDescriptorDeleter {
    void operator()(libusb_config_descriptor* desc) {
        libusb_free_config_descriptor(desc);
    }
};

using unique_config_descriptor = std::unique_ptr<libusb_config_descriptor, ConfigDescriptorDeleter>;

struct DeviceHandleDeleter {
    void operator()(libusb_device_handle* h) {
        libusb_close(h);
    }
};

using unique_device_handle = std::unique_ptr<libusb_device_handle, DeviceHandleDeleter>;

struct transfer_info {
    transfer_info(const char* name, uint16_t zero_mask, bool is_bulk_out)
        : name(name),
          transfer(libusb_alloc_transfer(0)),
          is_bulk_out(is_bulk_out),
          zero_mask(zero_mask) {}

    ~transfer_info() {
        libusb_free_transfer(transfer);
    }

    const char* name;
    libusb_transfer* transfer;
    bool is_bulk_out;
    bool transfer_complete;
    std::condition_variable cv;
    std::mutex mutex;
    uint16_t zero_mask;

    void Notify() {
        LOG(DEBUG) << "notifying " << name << " transfer complete";
        transfer_complete = true;
        cv.notify_one();
    }
};

namespace libusb {
struct usb_handle : public ::usb_handle {
    usb_handle(const std::string& device_address, const std::string& serial,
               unique_device_handle&& device_handle, uint8_t interface, uint8_t bulk_in,
               uint8_t bulk_out, size_t zero_mask, size_t max_packet_size)
        : device_address(device_address),
          serial(serial),
          closing(false),
          device_handle(device_handle.release()),
          read("read", zero_mask, false),
          write("write", zero_mask, true),
          interface(interface),
          bulk_in(bulk_in),
          bulk_out(bulk_out),
          max_packet_size(max_packet_size) {}

    ~usb_handle() {
        Close();
    }

    void Close() {
        std::unique_lock<std::mutex> lock(device_handle_mutex);
        // Cancelling transfers will trigger more Closes, so make sure this only happens once.
        if (closing) {
            return;
        }
        closing = true;

        // Make sure that no new transfers come in.
        libusb_device_handle* handle = device_handle;
        if (!handle) {
            return;
        }

        device_handle = nullptr;

        // Cancel already dispatched transfers.
        libusb_cancel_transfer(read.transfer);
        libusb_cancel_transfer(write.transfer);

        libusb_release_interface(handle, interface);
        libusb_close(handle);
    }

    std::string device_address;
    std::string serial;

    std::atomic<bool> closing;
    std::mutex device_handle_mutex;
    libusb_device_handle* device_handle;

    transfer_info read;
    transfer_info write;

    uint8_t interface;
    uint8_t bulk_in;
    uint8_t bulk_out;

    size_t max_packet_size;
};

static auto& usb_handles = *new std::unordered_map<std::string, std::unique_ptr<usb_handle>>();
static auto& usb_handles_mutex = *new std::mutex();

static libusb_hotplug_callback_handle hotplug_handle;

static std::string get_device_address(libusb_device* device) {
    return StringPrintf("usb:%d:%d", libusb_get_bus_number(device),
                        libusb_get_device_address(device));
}

#if defined(__linux__)
static std::string get_device_serial_path(libusb_device* device) {
    uint8_t ports[7];
    int port_count = libusb_get_port_numbers(device, ports, 7);
    if (port_count < 0) return "";

    std::string path =
        StringPrintf("/sys/bus/usb/devices/%d-%d", libusb_get_bus_number(device), ports[0]);
    for (int port = 1; port < port_count; ++port) {
        path += StringPrintf(".%d", ports[port]);
    }
    path += "/serial";
    return path;
}

static std::string get_device_dev_path(libusb_device* device) {
    uint8_t ports[7];
    int port_count = libusb_get_port_numbers(device, ports, 7);
    if (port_count < 0) return "";
    return StringPrintf("/dev/bus/usb/%03u/%03u", libusb_get_bus_number(device), ports[0]);
}
#endif

static bool endpoint_is_output(uint8_t endpoint) {
    return (endpoint & LIBUSB_ENDPOINT_DIR_MASK) == LIBUSB_ENDPOINT_OUT;
}

static bool should_perform_zero_transfer(uint8_t endpoint, size_t write_length, uint16_t zero_mask) {
    return endpoint_is_output(endpoint) && write_length != 0 && zero_mask != 0 &&
           (write_length & zero_mask) == 0;
}

static void process_device(libusb_device* device) {
    std::string device_address = get_device_address(device);
    std::string device_serial;

    // Figure out if we want to open the device.
    libusb_device_descriptor device_desc;
    int rc = libusb_get_device_descriptor(device, &device_desc);
    if (rc != 0) {
        LOG(WARNING) << "failed to get device descriptor for device at " << device_address << ": "
                     << libusb_error_name(rc);
        return;
    }

    if (device_desc.bDeviceClass != LIBUSB_CLASS_PER_INTERFACE) {
        // Assume that all Android devices have the device class set to per interface.
        // TODO: Is this assumption valid?
        LOG(VERBOSE) << "skipping device with incorrect class at " << device_address;
        return;
    }

    libusb_config_descriptor* config_raw;
    rc = libusb_get_active_config_descriptor(device, &config_raw);
    if (rc != 0) {
        LOG(WARNING) << "failed to get active config descriptor for device at " << device_address
                     << ": " << libusb_error_name(rc);
        return;
    }
    const unique_config_descriptor config(config_raw);

    // Use size_t for interface_num so <iostream>s don't mangle it.
    size_t interface_num;
    uint16_t zero_mask = 0;
    uint8_t bulk_in = 0, bulk_out = 0;
    size_t packet_size = 0;
    bool found_adb = false;

    for (interface_num = 0; interface_num < config->bNumInterfaces; ++interface_num) {
        const libusb_interface& interface = config->interface[interface_num];
        if (interface.num_altsetting != 1) {
            // Assume that interfaces with alternate settings aren't adb interfaces.
            // TODO: Is this assumption valid?
            LOG(VERBOSE) << "skipping interface with incorrect num_altsetting at " << device_address
                         << " (interface " << interface_num << ")";
            continue;
        }

        const libusb_interface_descriptor& interface_desc = interface.altsetting[0];
        if (!is_adb_interface(interface_desc.bInterfaceClass, interface_desc.bInterfaceSubClass,
                              interface_desc.bInterfaceProtocol)) {
            LOG(VERBOSE) << "skipping non-adb interface at " << device_address << " (interface "
                         << interface_num << ")";
            continue;
        }

        LOG(VERBOSE) << "found potential adb interface at " << device_address << " (interface "
                     << interface_num << ")";

        bool found_in = false;
        bool found_out = false;
        for (size_t endpoint_num = 0; endpoint_num < interface_desc.bNumEndpoints; ++endpoint_num) {
            const auto& endpoint_desc = interface_desc.endpoint[endpoint_num];
            const uint8_t endpoint_addr = endpoint_desc.bEndpointAddress;
            const uint8_t endpoint_attr = endpoint_desc.bmAttributes;

            const uint8_t transfer_type = endpoint_attr & LIBUSB_TRANSFER_TYPE_MASK;

            if (transfer_type != LIBUSB_TRANSFER_TYPE_BULK) {
                continue;
            }

            if (endpoint_is_output(endpoint_addr) && !found_out) {
                found_out = true;
                bulk_out = endpoint_addr;
                zero_mask = endpoint_desc.wMaxPacketSize - 1;
            } else if (!endpoint_is_output(endpoint_addr) && !found_in) {
                found_in = true;
                bulk_in = endpoint_addr;
            }

            size_t endpoint_packet_size = endpoint_desc.wMaxPacketSize;
            CHECK(endpoint_packet_size != 0);
            if (packet_size == 0) {
                packet_size = endpoint_packet_size;
            } else {
                CHECK(packet_size == endpoint_packet_size);
            }
        }

        if (found_in && found_out) {
            found_adb = true;
            break;
        } else {
            LOG(VERBOSE) << "rejecting potential adb interface at " << device_address
                         << "(interface " << interface_num << "): missing bulk endpoints "
                         << "(found_in = " << found_in << ", found_out = " << found_out << ")";
        }
    }

    if (!found_adb) {
        LOG(VERBOSE) << "skipping device with no adb interfaces at " << device_address;
        return;
    }

    {
        std::unique_lock<std::mutex> lock(usb_handles_mutex);
        if (usb_handles.find(device_address) != usb_handles.end()) {
            LOG(VERBOSE) << "device at " << device_address
                         << " has already been registered, skipping";
            return;
        }
    }

    bool writable = true;
    libusb_device_handle* handle_raw = nullptr;
    rc = libusb_open(device, &handle_raw);
    unique_device_handle handle(handle_raw);
    if (rc == 0) {
        LOG(DEBUG) << "successfully opened adb device at " << device_address << ", "
                   << StringPrintf("bulk_in = %#x, bulk_out = %#x", bulk_in, bulk_out);

        device_serial.resize(255);
        rc = libusb_get_string_descriptor_ascii(handle_raw, device_desc.iSerialNumber,
                                                reinterpret_cast<unsigned char*>(&device_serial[0]),
                                                device_serial.length());
        if (rc == 0) {
            LOG(WARNING) << "received empty serial from device at " << device_address;
            return;
        } else if (rc < 0) {
            LOG(WARNING) << "failed to get serial from device at " << device_address
                         << libusb_error_name(rc);
            return;
        }
        device_serial.resize(rc);

        // WARNING: this isn't released via RAII.
        rc = libusb_claim_interface(handle.get(), interface_num);
        if (rc != 0) {
            LOG(WARNING) << "failed to claim adb interface for device '" << device_serial << "'"
                         << libusb_error_name(rc);
            return;
        }

        rc = libusb_set_interface_alt_setting(handle.get(), interface_num, 0);
        if (rc != 0) {
            LOG(WARNING) << "failed to set interface alt setting for device '" << device_serial
                         << "'" << libusb_error_name(rc);
            return;
        }

        for (uint8_t endpoint : {bulk_in, bulk_out}) {
            rc = libusb_clear_halt(handle.get(), endpoint);
            if (rc != 0) {
                LOG(WARNING) << "failed to clear halt on device '" << device_serial
                             << "' endpoint 0x" << std::hex << endpoint << ": "
                             << libusb_error_name(rc);
                libusb_release_interface(handle.get(), interface_num);
                return;
            }
        }
    } else {
        LOG(WARNING) << "failed to open usb device at " << device_address << ": "
                     << libusb_error_name(rc);
        writable = false;

#if defined(__linux__)
        // libusb doesn't think we should be messing around with devices we don't have
        // write access to, but Linux at least lets us get the serial number anyway.
        if (!android::base::ReadFileToString(get_device_serial_path(device), &device_serial)) {
            // We don't actually want to treat an unknown serial as an error because
            // devices aren't able to communicate a serial number in early bringup.
            // http://b/20883914
            device_serial = "unknown";
        }
        device_serial = android::base::Trim(device_serial);
#else
        // On Mac OS and Windows, we're screwed. But I don't think this situation actually
        // happens on those OSes.
        return;
#endif
    }

    std::unique_ptr<usb_handle> result(new usb_handle(device_address, device_serial,
                                                      std::move(handle), interface_num, bulk_in,
                                                      bulk_out, zero_mask, packet_size));
    usb_handle* usb_handle_raw = result.get();

    {
        std::unique_lock<std::mutex> lock(usb_handles_mutex);
        usb_handles[device_address] = std::move(result);

        register_usb_transport(usb_handle_raw, device_serial.c_str(), device_address.c_str(),
                               writable);
    }
    LOG(INFO) << "registered new usb device '" << device_serial << "'";
}

static std::atomic<int> connecting_devices(0);

static void device_connected(libusb_device* device) {
#if defined(__linux__)
    // Android's host linux libusb uses netlink instead of udev for device hotplug notification,
    // which means we can get hotplug notifications before udev has updated ownership/perms on the
    // device. Since we're not going to be able to link against the system's libudev any time soon,
    // hack around this by inserting a sleep.
    auto thread = std::thread([device]() {
        std::string device_path = get_device_dev_path(device);
        std::this_thread::sleep_for(std::chrono::seconds(1));

        process_device(device);
        if (--connecting_devices == 0) {
            adb_notify_device_scan_complete();
        }
    });
    thread.detach();
#else
    process_device(device);
#endif
}

static void device_disconnected(libusb_device* device) {
    std::string device_address = get_device_address(device);

    LOG(INFO) << "device disconnected: " << device_address;
    std::unique_lock<std::mutex> lock(usb_handles_mutex);
    auto it = usb_handles.find(device_address);
    if (it != usb_handles.end()) {
        if (!it->second->device_handle) {
            // If the handle is null, we were never able to open the device.

            // Temporarily release the usb handles mutex to avoid deadlock.
            std::unique_ptr<usb_handle> handle = std::move(it->second);
            usb_handles.erase(it);
            lock.unlock();
            unregister_usb_transport(handle.get());
            lock.lock();
        } else {
            // Closure of the transport will erase the usb_handle.
        }
    }
}

static auto& hotplug_queue = *new BlockingQueue<std::pair<libusb_hotplug_event, libusb_device*>>();
static void hotplug_thread() {
    adb_thread_setname("libusb hotplug");
    while (true) {
        hotplug_queue.PopAll([](std::pair<libusb_hotplug_event, libusb_device*> pair) {
            libusb_hotplug_event event = pair.first;
            libusb_device* device = pair.second;
            if (event == LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED) {
                device_connected(device);
            } else if (event == LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT) {
                device_disconnected(device);
            }
        });
    }
}

static LIBUSB_CALL int hotplug_callback(libusb_context*, libusb_device* device,
                                        libusb_hotplug_event event, void*) {
    // We're called with the libusb lock taken. Call these on a separate thread outside of this
    // function so that the usb_handle mutex is always taken before the libusb mutex.
    static std::once_flag once;
    std::call_once(once, []() { std::thread(hotplug_thread).detach(); });

    if (event == LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED) {
        ++connecting_devices;
    }
    hotplug_queue.Push({event, device});
    return 0;
}

void usb_init() {
    LOG(DEBUG) << "initializing libusb...";
    int rc = libusb_init(nullptr);
    if (rc != 0) {
        LOG(FATAL) << "failed to initialize libusb: " << libusb_error_name(rc);
    }

    // Register the hotplug callback.
    rc = libusb_hotplug_register_callback(
        nullptr, static_cast<libusb_hotplug_event>(LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED |
                                                   LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT),
        LIBUSB_HOTPLUG_ENUMERATE, LIBUSB_HOTPLUG_MATCH_ANY, LIBUSB_HOTPLUG_MATCH_ANY,
        LIBUSB_CLASS_PER_INTERFACE, hotplug_callback, nullptr, &hotplug_handle);

    if (rc != LIBUSB_SUCCESS) {
        LOG(FATAL) << "failed to register libusb hotplug callback";
    }

    // Spawn a thread for libusb_handle_events.
    std::thread([]() {
        adb_thread_setname("libusb");
        while (true) {
            libusb_handle_events(nullptr);
        }
    }).detach();
}

void usb_cleanup() {
    libusb_hotplug_deregister_callback(nullptr, hotplug_handle);
}

static LIBUSB_CALL void transfer_callback(libusb_transfer* transfer) {
    transfer_info* info = static_cast<transfer_info*>(transfer->user_data);

    LOG(DEBUG) << info->name << " transfer callback entered";

    // Make sure that the original submitter has made it to the condition_variable wait.
    std::unique_lock<std::mutex> lock(info->mutex);

    LOG(DEBUG) << info->name << " callback successfully acquired lock";

    if (transfer->status != LIBUSB_TRANSFER_COMPLETED) {
        LOG(WARNING) << info->name << " transfer failed: " << libusb_error_name(transfer->status);
        info->Notify();
        return;
    }

    // usb_read() can return when receiving some data.
    if (info->is_bulk_out && transfer->actual_length != transfer->length) {
        LOG(DEBUG) << info->name << " transfer incomplete, resubmitting";
        transfer->length -= transfer->actual_length;
        transfer->buffer += transfer->actual_length;
        int rc = libusb_submit_transfer(transfer);
        if (rc != 0) {
            LOG(WARNING) << "failed to submit " << info->name
                         << " transfer: " << libusb_error_name(rc);
            transfer->status = LIBUSB_TRANSFER_ERROR;
            info->Notify();
        }
        return;
    }

    if (should_perform_zero_transfer(transfer->endpoint, transfer->length, info->zero_mask)) {
        LOG(DEBUG) << "submitting zero-length write";
        transfer->length = 0;
        int rc = libusb_submit_transfer(transfer);
        if (rc != 0) {
            LOG(WARNING) << "failed to submit zero-length write: " << libusb_error_name(rc);
            transfer->status = LIBUSB_TRANSFER_ERROR;
            info->Notify();
        }
        return;
    }

    LOG(VERBOSE) << info->name << "transfer fully complete";
    info->Notify();
}

// Dispatch a libusb transfer, unlock |device_lock|, and then wait for the result.
static int perform_usb_transfer(usb_handle* h, transfer_info* info,
                                std::unique_lock<std::mutex> device_lock) {
    libusb_transfer* transfer = info->transfer;

    transfer->user_data = info;
    transfer->callback = transfer_callback;

    LOG(DEBUG) << "locking " << info->name << " transfer_info mutex";
    std::unique_lock<std::mutex> lock(info->mutex);
    info->transfer_complete = false;
    LOG(DEBUG) << "submitting " << info->name << " transfer";
    int rc = libusb_submit_transfer(transfer);
    if (rc != 0) {
        LOG(WARNING) << "failed to submit " << info->name << " transfer: " << libusb_error_name(rc);
        errno = EIO;
        return -1;
    }

    LOG(DEBUG) << info->name << " transfer successfully submitted";
    device_lock.unlock();
    info->cv.wait(lock, [info]() { return info->transfer_complete; });
    if (transfer->status != 0) {
        errno = EIO;
        return -1;
    }

    return 0;
}

int usb_write(usb_handle* h, const void* d, int len) {
    LOG(DEBUG) << "usb_write of length " << len;

    std::unique_lock<std::mutex> lock(h->device_handle_mutex);
    if (!h->device_handle) {
        errno = EIO;
        return -1;
    }

    transfer_info* info = &h->write;
    info->transfer->dev_handle = h->device_handle;
    info->transfer->flags = 0;
    info->transfer->endpoint = h->bulk_out;
    info->transfer->type = LIBUSB_TRANSFER_TYPE_BULK;
    info->transfer->length = len;
    info->transfer->buffer = reinterpret_cast<unsigned char*>(const_cast<void*>(d));
    info->transfer->num_iso_packets = 0;

    int rc = perform_usb_transfer(h, info, std::move(lock));
    LOG(DEBUG) << "usb_write(" << len << ") = " << rc;
    return rc;
}

int usb_read(usb_handle* h, void* d, int len) {
    LOG(DEBUG) << "usb_read of length " << len;

    std::unique_lock<std::mutex> lock(h->device_handle_mutex);
    if (!h->device_handle) {
        errno = EIO;
        return -1;
    }

    transfer_info* info = &h->read;
    info->transfer->dev_handle = h->device_handle;
    info->transfer->flags = 0;
    info->transfer->endpoint = h->bulk_in;
    info->transfer->type = LIBUSB_TRANSFER_TYPE_BULK;
    info->transfer->length = len;
    info->transfer->buffer = reinterpret_cast<unsigned char*>(d);
    info->transfer->num_iso_packets = 0;

    int rc = perform_usb_transfer(h, info, std::move(lock));
    LOG(DEBUG) << "usb_read(" << len << ") = " << rc << ", actual_length "
               << info->transfer->actual_length;
    if (rc < 0) {
        return rc;
    }
    return info->transfer->actual_length;
}

int usb_close(usb_handle* h) {
    std::unique_lock<std::mutex> lock(usb_handles_mutex);
    auto it = usb_handles.find(h->device_address);
    if (it == usb_handles.end()) {
        LOG(FATAL) << "attempted to close unregistered usb_handle for '" << h->serial << "'";
    }
    usb_handles.erase(h->device_address);
    return 0;
}

void usb_kick(usb_handle* h) {
    h->Close();
}

size_t usb_get_max_packet_size(usb_handle* h) {
    CHECK(h->max_packet_size != 0);
    return h->max_packet_size;
}

} // namespace libusb

/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include <err.h>
#include <stdio.h>
#include <unistd.h>

#include <optional>
#include <string>
#include <vector>

#include <libusb/libusb.h>

static bool is_adb_device(libusb_device* device) {
    libusb_device_descriptor device_desc;
    libusb_get_device_descriptor(device, &device_desc);
    if (device_desc.bDeviceClass != 0) {
        return false;
    }

    libusb_config_descriptor* config_desc;
    int rc = libusb_get_active_config_descriptor(device, &config_desc);
    if (rc != 0) {
        fprintf(stderr, "failed to get config descriptor for device %u:%u: %s\n",
                libusb_get_bus_number(device), libusb_get_port_number(device),
                libusb_error_name(rc));
        return false;
    }

    for (size_t i = 0; i < config_desc->bNumInterfaces; ++i) {
        const libusb_interface* interface = &config_desc->interface[i];
        for (int j = 0; j < interface->num_altsetting; ++j) {
            const libusb_interface_descriptor* interface_descriptor = &interface->altsetting[j];
            if (interface_descriptor->bInterfaceClass == 0xff &&
                interface_descriptor->bInterfaceSubClass == 0x42 &&
                interface_descriptor->bInterfaceProtocol == 1) {
                return true;
            }
        }
    }

    return false;
}

static std::optional<std::vector<uint8_t>> get_descriptor(libusb_device_handle* handle,
                                                          uint8_t type, uint8_t index,
                                                          uint16_t length) {
    std::vector<uint8_t> result;
    result.resize(length);
    int rc = libusb_get_descriptor(handle, type, index, result.data(), result.size());
    if (rc < 0) {
        fprintf(stderr, "libusb_get_descriptor failed: %s\n", libusb_error_name(rc));
        return std::nullopt;
    }
    result.resize(rc);
    return result;
}

static std::optional<std::string> get_string_descriptor(libusb_device_handle* handle,
                                                        uint8_t index) {
    std::string result;
    result.resize(4096);
    int rc = libusb_get_string_descriptor_ascii(
            handle, index, reinterpret_cast<uint8_t*>(result.data()), result.size());
    if (rc < 0) {
        fprintf(stderr, "libusb_get_string_descriptor_ascii failed: %s\n", libusb_error_name(rc));
        return std::nullopt;
    }
    result.resize(rc);
    return result;
}

static void check_ms_os_desc_v1(libusb_device_handle* device_handle, const std::string& serial) {
    auto os_desc = get_descriptor(device_handle, 0x03, 0xEE, 0x12);
    if (!os_desc) {
        errx(1, "failed to retrieve MS OS descriptor");
    }

    if (os_desc->size() != 0x12) {
        errx(1, "os descriptor size mismatch");
    }

    if (memcmp(os_desc->data() + 2, u"MSFT100\0", 14) != 0) {
        errx(1, "os descriptor signature mismatch");
    }

    uint8_t vendor_code = (*os_desc)[16];
    uint8_t pad = (*os_desc)[17];

    if (pad != 0) {
        errx(1, "os descriptor padding non-zero");
    }

    std::vector<uint8_t> data;
    data.resize(0x10);
    int rc = libusb_control_transfer(device_handle, 0xC0, vendor_code, 0x00, 0x04, data.data(),
                                     data.size(), 0);
    if (rc != 0x10) {
        errx(1, "failed to retrieve MS OS v1 compat descriptor header: %s", libusb_error_name(rc));
    }

    struct __attribute__((packed)) ms_os_desc_v1_header {
        uint32_t dwLength;
        uint16_t bcdVersion;
        uint16_t wIndex;
        uint8_t bCount;
        uint8_t reserved[7];
    };
    static_assert(sizeof(ms_os_desc_v1_header) == 0x10);

    ms_os_desc_v1_header hdr;
    memcpy(&hdr, data.data(), data.size());

    data.resize(hdr.dwLength);
    rc = libusb_control_transfer(device_handle, 0xC0, vendor_code, 0x00, 0x04, data.data(),
                                 data.size(), 0);
    if (static_cast<size_t>(rc) != data.size()) {
        errx(1, "failed to retrieve MS OS v1 compat descriptor: %s", libusb_error_name(rc));
    }

    memcpy(&hdr, data.data(), data.size());

    struct __attribute__((packed)) ms_os_desc_v1_function {
        uint8_t bFirstInterfaceNumber;
        uint8_t reserved1;
        uint8_t compatibleID[8];
        uint8_t subCompatibleID[8];
        uint8_t reserved2[6];
    };

    if (sizeof(ms_os_desc_v1_header) + hdr.bCount * sizeof(ms_os_desc_v1_function) != data.size()) {
        errx(1, "MS OS v1 compat descriptor size mismatch");
    }

    for (int i = 0; i < hdr.bCount; ++i) {
        ms_os_desc_v1_function function;
        memcpy(&function,
               data.data() + sizeof(ms_os_desc_v1_header) + i * sizeof(ms_os_desc_v1_function),
               sizeof(function));
        if (memcmp("WINUSB\0\0", function.compatibleID, 8) == 0) {
            return;
        }
    }

    errx(1, "failed to find v1 MS OS descriptor specifying WinUSB for device %s", serial.c_str());
}

int main(int argc, char** argv) {
    libusb_context* ctx;
    if (libusb_init(&ctx) != 0) {
        errx(1, "failed to initialize libusb context");
    }

    libusb_device** device_list = nullptr;
    ssize_t device_count = libusb_get_device_list(ctx, &device_list);
    if (device_count < 0) {
        errx(1, "libusb_get_device_list failed");
    }

    const char* expected_serial = getenv("ANDROID_SERIAL");
    bool found = false;

    for (ssize_t i = 0; i < device_count; ++i) {
        libusb_device* device = device_list[i];
        if (!is_adb_device(device)) {
            continue;
        }

        libusb_device_handle* device_handle = nullptr;
        int rc = libusb_open(device, &device_handle);
        if (rc != 0) {
            fprintf(stderr, "failed to open device %u:%u: %s\n", libusb_get_bus_number(device),
                    libusb_get_port_number(device), libusb_error_name(rc));
            continue;
        }

        libusb_device_descriptor device_desc;
        libusb_get_device_descriptor(device, &device_desc);

        std::optional<std::string> serial =
                get_string_descriptor(device_handle, device_desc.iSerialNumber);
        if (!serial) {
            errx(1, "failed to get serial for device %u:%u", libusb_get_bus_number(device),
                 libusb_get_port_number(device));
        }

        if (expected_serial && *serial != expected_serial) {
            fprintf(stderr, "skipping %s (wanted %s)\n", serial->c_str(), expected_serial);
            continue;
        }

        // Check for MS OS Descriptor v1.
        // https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpeusb/c2f351f9-84d2-4a1b-9fe3-a6ca195f84d0
        fprintf(stderr, "fetching v1 OS descriptor from device %s\n", serial->c_str());
        check_ms_os_desc_v1(device_handle, *serial);
        fprintf(stderr, "found v1 OS descriptor for device %s\n", serial->c_str());

        // TODO: Read BOS for MS OS Descriptor 2.0 descriptors:
        // http://download.microsoft.com/download/3/5/6/3563ED4A-F318-4B66-A181-AB1D8F6FD42D/MS_OS_2_0_desc.docx

        found = true;
    }

    if (expected_serial && !found) {
        errx(1, "failed to find device with serial %s", expected_serial);
    }
    return 0;
}

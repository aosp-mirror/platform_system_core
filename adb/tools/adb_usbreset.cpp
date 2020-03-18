// Copyright (C) 2020 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <err.h>
#include <getopt.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>

#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include <libusb/libusb.h>

struct AllDevices {};
struct SingleDevice {};
struct Serial {
    std::string_view serial;
};

using DeviceSelection = std::variant<std::monostate, AllDevices, SingleDevice, Serial>;

[[noreturn]] static void Usage(int rc) {
    fprintf(stderr, "usage: [ANDROID_SERIAL=SERIAL] usbreset [-d] [-s SERIAL]\n");
    fprintf(stderr, "\t-a --all\t\tReset all connected devices\n");
    fprintf(stderr, "\t-d --device\t\tReset the single connected device\n");
    fprintf(stderr, "\t-s --serial\t\tReset device with specified serial\n");
    exit(rc);
}

static void SetOption(DeviceSelection* out, DeviceSelection in) {
    if (!std::get_if<std::monostate>(out)) {
        printf("error: multiple device selection options provided\n");
        Usage(1);
    }

    *out = in;
}

static __attribute__((format(printf, 2, 3))) void PrintLibusbError(int err, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    vprintf(fmt, args);
    va_end(args);

    printf(": %s", libusb_strerror(static_cast<libusb_error>(err)));
}

static bool IsAdbInterface(const libusb_interface_descriptor* desc) {
    return desc->bInterfaceClass == 0xFF && desc->bInterfaceSubClass == 0x42 &&
           desc->bInterfaceProtocol == 0x1;
}

int main(int argc, char** argv) {
    std::variant<std::monostate, AllDevices, SingleDevice, Serial> selection;

    static constexpr struct option long_opts[] = {
            {"all", 0, 0, 'a'},    {"help", 0, 0, 'h'}, {"serial", required_argument, 0, 's'},
            {"device", 0, 0, 'd'}, {0, 0, 0, 0},
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "adhs:", long_opts, nullptr)) != -1) {
        if (opt == 'h') {
            Usage(0);
        } else if (opt == 'a') {
            SetOption(&selection, AllDevices{});
        } else if (opt == 's') {
            SetOption(&selection, Serial{optarg});
        } else if (opt == 'd') {
            SetOption(&selection, Serial{optarg});
        } else {
            errx(1, "unknown option: '%c'", opt);
        }
    }

    if (std::get_if<std::monostate>(&selection)) {
        const char* env = getenv("ANDROID_SERIAL");
        if (env) {
            SetOption(&selection, Serial{env});
        } else {
            fprintf(stderr, "adb_usbreset: no device specified\n");
            Usage(1);
        }
    }

    libusb_context* ctx;
    int rc = libusb_init(&ctx);
    if (rc != LIBUSB_SUCCESS) {
        PrintLibusbError(rc, "error: failed to initialize libusb");
        exit(1);
    }

    libusb_device** device_list;
    ssize_t device_count = libusb_get_device_list(ctx, &device_list);
    if (device_count < 0) {
        PrintLibusbError(device_count, "error: failed to list devices");
        exit(1);
    }

    std::vector<std::pair<std::string, libusb_device_handle*>> selected_devices;
    for (int i = 0; i < device_count; ++i) {
        libusb_device* device = device_list[i];
        libusb_device_descriptor device_desc;

        // Always succeeds for LIBUSB_API_VERSION >= 0x01000102.
        libusb_get_device_descriptor(device, &device_desc);
        static_assert(LIBUSB_API_VERSION >= 0x01000102);

        libusb_config_descriptor* config_desc;
        rc = libusb_get_active_config_descriptor(device, &config_desc);
        if (rc != 0) {
            PrintLibusbError(rc, "warning: failed to get config descriptor");
            continue;
        }

        bool found_adb_interface = false;
        for (int i = 0; i < config_desc->bNumInterfaces; ++i) {
            if (IsAdbInterface(&config_desc->interface[i].altsetting[0])) {
                found_adb_interface = true;
                break;
            }
        }

        if (found_adb_interface) {
            libusb_device_handle* device_handle;
            rc = libusb_open(device, &device_handle);
            if (rc != 0) {
                PrintLibusbError(rc, "warning: failed to open device");
                continue;
            }

            char buf[128];
            rc = libusb_get_string_descriptor_ascii(device_handle, device_desc.iSerialNumber,
                                                    reinterpret_cast<unsigned char*>(buf),
                                                    sizeof(buf));

            if (rc < 0) {
                PrintLibusbError(rc, "warning: failed to get device serial");
                continue;
            }

            std::string serial(buf, buf + rc);
            if (auto s = std::get_if<Serial>(&selection)) {
                if (s->serial == serial) {
                    selected_devices.push_back(std::make_pair(std::move(serial), device_handle));
                }
            } else {
                selected_devices.push_back(std::make_pair(std::move(serial), device_handle));
            }
        }
    }

    if (selected_devices.empty()) {
        errx(1, "no devices match criteria");
    } else if (std::get_if<SingleDevice>(&selection) && selected_devices.size() != 1) {
        errx(1, "more than 1 device connected");
    }

    bool success = true;
    for (auto& [serial, device_handle] : selected_devices) {
        rc = libusb_reset_device(device_handle);
        // libusb_reset_device will try to restore the previous state, and will return
        // LIBUSB_ERROR_NOT_FOUND if it can't.
        if (rc == 0 || rc == LIBUSB_ERROR_NOT_FOUND) {
            printf("%s: successfully reset\n", serial.c_str());
        } else {
            PrintLibusbError(rc, "%s: failed to reset", serial.c_str());
            success = false;
        }
    }

    return !success;
}

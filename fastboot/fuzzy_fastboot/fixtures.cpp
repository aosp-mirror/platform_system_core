/*
 * Copyright (C) 2018 The Android Open Source Project
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
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <map>
#include <random>
#include <regex>
#include <set>
#include <thread>
#include <vector>

#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <gtest/gtest.h>

#include "fastboot_driver.h"
#include "tcp.h"
#include "usb.h"

#include "extensions.h"
#include "fixtures.h"
#include "test_utils.h"
#include "transport_sniffer.h"

using namespace std::literals::chrono_literals;

namespace fastboot {

int FastBootTest::MatchFastboot(usb_ifc_info* info, const std::string& local_serial) {
    if (info->ifc_class != 0xff || info->ifc_subclass != 0x42 || info->ifc_protocol != 0x03) {
        return -1;
    }

    cb_scratch = info->device_path;

    // require matching serial number or device path if requested
    // at the command line with the -s option.
    if (!local_serial.empty() && local_serial != info->serial_number &&
        local_serial != info->device_path)
        return -1;
    return 0;
}

bool FastBootTest::IsFastbootOverTcp() {
    return android::base::StartsWith(device_serial, "tcp:");
}

bool FastBootTest::UsbStillAvailible() {
    if (IsFastbootOverTcp()) return true;

    // For some reason someone decided to prefix the path with "usb:"
    std::string prefix("usb:");
    if (std::equal(prefix.begin(), prefix.end(), device_path.begin())) {
        std::string fname(device_path.begin() + prefix.size(), device_path.end());
        std::string real_path =
                android::base::StringPrintf("/sys/bus/usb/devices/%s/serial", fname.c_str());
        std::ifstream f(real_path.c_str());
        return f.good();
    }
    exit(-1);  // This should never happen
    return true;
}

bool FastBootTest::UserSpaceFastboot() {
    std::string value;
    fb->GetVar("is-userspace", &value);
    return value == "yes";
}

RetCode FastBootTest::DownloadCommand(uint32_t size, std::string* response,
                                      std::vector<std::string>* info) {
    return fb->DownloadCommand(size, response, info);
}

RetCode FastBootTest::SendBuffer(const std::vector<char>& buf) {
    return fb->SendBuffer(buf);
}

RetCode FastBootTest::HandleResponse(std::string* response, std::vector<std::string>* info,
                                     int* dsize) {
    return fb->HandleResponse(response, info, dsize);
}

void FastBootTest::SetUp() {
    if (device_path != "") {               // make sure the device is still connected
        ASSERT_TRUE(UsbStillAvailible());  // The device disconnected
    }

    if (IsFastbootOverTcp()) {
        ConnectTcpFastbootDevice();
    } else {
        const auto matcher = [](usb_ifc_info* info) -> int {
            return MatchFastboot(info, device_serial);
        };
        for (int i = 0; i < MAX_USB_TRIES && !transport; i++) {
            std::unique_ptr<UsbTransport> usb = usb_open(matcher, USB_TIMEOUT);
            if (usb)
                transport = std::unique_ptr<TransportSniffer>(
                        new TransportSniffer(std::move(usb), serial_port));
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }

    ASSERT_TRUE(transport);  // no nullptr

    if (device_path == "") {  // We set it the first time, then make sure it never changes
        device_path = cb_scratch;
    } else {
        ASSERT_EQ(device_path, cb_scratch);  // The path can not change
    }
    fb = std::unique_ptr<FastBootDriver>(new FastBootDriver(std::move(transport), {}, true));
    // No error checking since non-A/B devices may not support the command
    fb->GetVar("current-slot", &initial_slot);
}

void FastBootTest::TearDown() {
    EXPECT_TRUE(UsbStillAvailible()) << USB_PORT_GONE;
    // No error checking since non-A/B devices may not support the command
    fb->SetActive(initial_slot);

    TearDownSerial();

    fb.reset();

    if (transport) {
        transport.reset();
    }

    ASSERT_TRUE(UsbStillAvailible()) << USB_PORT_GONE;
}

// TODO, this should eventually be piped to a file instead of stdout
void FastBootTest::TearDownSerial() {
    if (IsFastbootOverTcp()) return;

    if (!transport) return;
    // One last read from serial
    transport->ProcessSerial();
    if (HasFailure()) {
        // TODO, print commands leading up
        printf("<<<<<<<< TRACE BEGIN >>>>>>>>>\n");
        printf("%s", transport->CreateTrace().c_str());
        printf("<<<<<<<< TRACE END >>>>>>>>>\n");
        // std::vector<std::pair<const TransferType, const std::vector<char>>>  prev =
        // transport->Transfers();
    }
}

void FastBootTest::ConnectTcpFastbootDevice() {
    for (int i = 0; i < MAX_TCP_TRIES && !transport; i++) {
        std::string error;
        std::unique_ptr<Transport> tcp(
                tcp::Connect(device_serial.substr(4), tcp::kDefaultPort, &error).release());
        if (tcp)
            transport = std::unique_ptr<TransportSniffer>(new TransportSniffer(std::move(tcp), 0));
        if (transport != nullptr) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

void FastBootTest::ReconnectFastbootDevice() {
    fb.reset();
    transport.reset();

    if (IsFastbootOverTcp()) {
        ConnectTcpFastbootDevice();
        device_path = cb_scratch;
        fb = std::unique_ptr<FastBootDriver>(new FastBootDriver(std::move(transport), {}, true));
        return;
    }

    while (UsbStillAvailible())
        ;
    printf("WAITING FOR DEVICE\n");
    // Need to wait for device
    const auto matcher = [](usb_ifc_info* info) -> int {
        return MatchFastboot(info, device_serial);
    };
    while (!transport) {
        std::unique_ptr<UsbTransport> usb = usb_open(matcher, USB_TIMEOUT);
        if (usb) {
            transport = std::unique_ptr<TransportSniffer>(
                    new TransportSniffer(std::move(usb), serial_port));
        }
        std::this_thread::sleep_for(1s);
    }
    device_path = cb_scratch;
    fb = std::unique_ptr<FastBootDriver>(new FastBootDriver(std::move(transport), {}, true));
}

void FastBootTest::SetLockState(bool unlock, bool assert_change) {
    if (!fb) {
        return;
    }

    // User space fastboot implementations are not allowed to communicate to
    // secure hardware and hence cannot lock/unlock the device.
    if (UserSpaceFastboot()) {
        return;
    }

    std::string resp;
    std::vector<std::string> info;
    // To avoid risk of bricking device, make sure unlock ability is set to 1
    ASSERT_EQ(fb->RawCommand("flashing get_unlock_ability", &resp, &info), SUCCESS)
            << "'flashing get_unlock_ability' failed";

    // There are two ways this can be reported, through info or the actual response
    if (!resp.empty()) {  // must be in the info response
        ASSERT_EQ(resp.back(), '1')
                << "Unlock ability must be set to 1 to avoid bricking device, see "
                   "'https://source.android.com/devices/bootloader/unlock-trusty'";
    } else {
        ASSERT_FALSE(info.empty()) << "'flashing get_unlock_ability' returned empty response";
        ASSERT_FALSE(info.back().empty()) << "Expected non-empty info response";
        ASSERT_EQ(info.back().back(), '1')
                << "Unlock ability must be set to 1 to avoid bricking device, see "
                   "'https://source.android.com/devices/bootloader/unlock-trusty'";
    }

    EXPECT_EQ(fb->GetVar("unlocked", &resp), SUCCESS) << "getvar:unlocked failed";
    ASSERT_TRUE(resp == "no" || resp == "yes")
            << "getvar:unlocked response was not 'no' or 'yes': " + resp;

    if ((unlock && resp == "no") || (!unlock && resp == "yes")) {
        std::string cmd = unlock ? "unlock" : "lock";
        ASSERT_EQ(fb->RawCommand("flashing " + cmd, &resp), SUCCESS)
                << "Attempting to change locked state, but 'flashing" + cmd + "' command failed";
        printf("PLEASE RESPOND TO PROMPT FOR '%sing' BOOTLOADER ON DEVICE\n", cmd.c_str());
        ReconnectFastbootDevice();
        if (assert_change) {
            ASSERT_EQ(fb->GetVar("unlocked", &resp), SUCCESS) << "getvar:unlocked failed";
            ASSERT_EQ(resp, unlock ? "yes" : "no")
                    << "getvar:unlocked response was not 'no' or 'yes': " + resp;
        }
        printf("SUCCESS\n");
    }
}

std::string FastBootTest::device_path = "";
std::string FastBootTest::cb_scratch = "";
std::string FastBootTest::initial_slot = "";
int FastBootTest::serial_port = 0;
std::string FastBootTest::device_serial = "";

template <bool UNLOCKED>
void ModeTest<UNLOCKED>::SetUp() {
    ASSERT_NO_FATAL_FAILURE(FastBootTest::SetUp());
    ASSERT_NO_FATAL_FAILURE(SetLockState(UNLOCKED));
}
// Need to instatiate it, so linker can find it later
template class ModeTest<true>;
template class ModeTest<false>;

void Fuzz::TearDown() {
    ASSERT_TRUE(UsbStillAvailible()) << USB_PORT_GONE;

    TearDownSerial();

    std::string tmp;
    if (fb->GetVar("product", &tmp) != SUCCESS) {
        printf("DEVICE UNRESPONSE, attempting to recover...");
        transport->Reset();
        printf("issued USB reset...");

        if (fb->GetVar("product", &tmp) != SUCCESS) {
            printf("FAIL\n");
            exit(-1);
        }
        printf("SUCCESS!\n");
    }

    if (transport) {
        transport.reset();
    }

    ASSERT_TRUE(UsbStillAvailible()) << USB_PORT_GONE;
}

template <bool UNLOCKED>
void ExtensionsPartition<UNLOCKED>::SetUp() {
    ASSERT_NO_FATAL_FAILURE(FastBootTest::SetUp());
    ASSERT_NO_FATAL_FAILURE(SetLockState(UNLOCKED));

    if (!fb) {
        return;
    }
    const std::string name = GetParam().first;

    std::string var;
    ASSERT_EQ(fb->GetVar("slot-count", &var), SUCCESS) << "Getting slot count failed";
    int32_t num_slots = strtol(var.c_str(), nullptr, 10);
    real_parts = GeneratePartitionNames(name, GetParam().second.slots ? num_slots : 0);

    ASSERT_EQ(fb->GetVar("partition-size:" + real_parts.front(), &var), SUCCESS)
            << "Getting partition size failed";
    part_size = strtoll(var.c_str(), nullptr, 16);
    ASSERT_GT(part_size, 0) << "Partition size reported was invalid";

    ASSERT_EQ(fb->GetVar("max-download-size", &var), SUCCESS) << "Getting max download size failed";
    max_dl = strtoll(var.c_str(), nullptr, 16);
    ASSERT_GT(max_dl, 0) << "Max download size reported was invalid";

    max_flash = std::min(part_size, max_dl);
}
template class ExtensionsPartition<true>;
template class ExtensionsPartition<false>;

}  // end namespace fastboot

/*
 * Copyright (C) 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
#include <android-base/file.h>
#include "fastboot.h"
#include "socket.h"
#include "socket_mock_fuzz.h"
#include "tcp.h"
#include "udp.h"
#include "vendor_boot_img_utils.h"

#include <fuzzer/FuzzedDataProvider.h>

using namespace std;

const size_t kYearMin = 2000;
const size_t kYearMax = 2127;
const size_t kMonthMin = 1;
const size_t kMonthMax = 12;
const size_t kDayMin = 1;
const size_t kDayMax = 31;
const size_t kVersionMin = 0;
const size_t kVersionMax = 127;
const size_t kMaxStringSize = 100;
const size_t kMinTimeout = 10;
const size_t kMaxTimeout = 3000;
const uint16_t kValidUdpPacketSize = 512;
const uint16_t kMinUdpPackets = 1;
const uint16_t kMaxUdpPackets = 10;

const string kValidTcpHandshakeString = "FB01";
const string kInvalidTcpHandshakeString = "FB00";
const string kValidRamdiskName = "default";
const string kVendorBootFile = "/tmp/vendorBootFile";
const string kRamdiskFile = "/tmp/ramdiskFile";
const char* kFsOptionsArray[] = {"casefold", "projid", "compress"};

class FastbootFuzzer {
  public:
    void Process(const uint8_t* data, size_t size);

  private:
    void InvokeParseApi();
    void InvokeSocket();
    void InvokeTcp();
    void InvokeUdp();
    void InvokeVendorBootImgUtils(const uint8_t* data, size_t size);
    bool MakeConnectedSockets(Socket::Protocol protocol, unique_ptr<Socket>* server,
                              unique_ptr<Socket>* client, const string& hostname);
    unique_ptr<FuzzedDataProvider> fdp_ = nullptr;
};

void FastbootFuzzer::InvokeParseApi() {
    boot_img_hdr_v1 hdr = {};
    FastBootTool fastBoot;

    int32_t year = fdp_->ConsumeIntegralInRange<int32_t>(kYearMin, kYearMax);
    int32_t month = fdp_->ConsumeIntegralInRange<int32_t>(kMonthMin, kMonthMax);
    int32_t day = fdp_->ConsumeIntegralInRange<int32_t>(kDayMin, kDayMax);
    string date = to_string(year) + "-" + to_string(month) + "-" + to_string(day);
    fastBoot.ParseOsPatchLevel(&hdr, date.c_str());

    int32_t major = fdp_->ConsumeIntegralInRange<int32_t>(kVersionMin, kVersionMax);
    int32_t minor = fdp_->ConsumeIntegralInRange<int32_t>(kVersionMin, kVersionMax);
    int32_t patch = fdp_->ConsumeIntegralInRange<int32_t>(kVersionMin, kVersionMax);
    string version = to_string(major) + "." + to_string(minor) + "." + to_string(patch);
    fastBoot.ParseOsVersion(&hdr, version.c_str());

    fastBoot.ParseFsOption(fdp_->PickValueInArray(kFsOptionsArray));
}

bool FastbootFuzzer::MakeConnectedSockets(Socket::Protocol protocol, unique_ptr<Socket>* server,
                                          unique_ptr<Socket>* client,
                                          const string& hostname = "localhost") {
    *server = Socket::NewServer(protocol, 0);
    if (*server == nullptr) {
        return false;
    }
    *client = Socket::NewClient(protocol, hostname, (*server)->GetLocalPort(), nullptr);
    if (*client == nullptr) {
        return false;
    }
    if (protocol == Socket::Protocol::kTcp) {
        *server = (*server)->Accept();
        if (*server == nullptr) {
            return false;
        }
    }
    return true;
}

void FastbootFuzzer::InvokeSocket() {
    unique_ptr<Socket> server, client;

    for (Socket::Protocol protocol : {Socket::Protocol::kUdp, Socket::Protocol::kTcp}) {
        if (MakeConnectedSockets(protocol, &server, &client)) {
            string message = fdp_->ConsumeRandomLengthString(kMaxStringSize);
            client->Send(message.c_str(), message.length());
            string received(message.length(), '\0');
            if (fdp_->ConsumeBool()) {
                client->Close();
            }
            if (fdp_->ConsumeBool()) {
                server->Close();
            }
            server->ReceiveAll(&received[0], received.length(),
                               /* timeout_ms */
                               fdp_->ConsumeIntegralInRange<size_t>(kMinTimeout, kMaxTimeout));
            server->Close();
            client->Close();
        }
    }
}

void FastbootFuzzer::InvokeTcp() {
    /* Using a raw SocketMockFuzz* here because ownership shall be passed to the Transport object */
    SocketMockFuzz* tcp_mock = new SocketMockFuzz;
    tcp_mock->ExpectSend(fdp_->ConsumeBool() ? kValidTcpHandshakeString
                                             : kInvalidTcpHandshakeString);
    tcp_mock->AddReceive(fdp_->ConsumeBool() ? kValidTcpHandshakeString
                                             : kInvalidTcpHandshakeString);

    string error;
    unique_ptr<Transport> transport = tcp::internal::Connect(unique_ptr<Socket>(tcp_mock), &error);

    if (transport.get()) {
        string write_message = fdp_->ConsumeRandomLengthString(kMaxStringSize);
        if (fdp_->ConsumeBool()) {
            tcp_mock->ExpectSend(write_message);
        } else {
            tcp_mock->ExpectSendFailure(write_message);
        }
        string read_message = fdp_->ConsumeRandomLengthString(kMaxStringSize);
        if (fdp_->ConsumeBool()) {
            tcp_mock->AddReceive(read_message);
        } else {
            tcp_mock->AddReceiveFailure();
        }

        transport->Write(write_message.data(), write_message.length());

        string buffer(read_message.length(), '\0');
        transport->Read(&buffer[0], buffer.length());

        transport->Close();
    }
}

static string PacketValue(uint16_t value) {
    return string{static_cast<char>(value >> 8), static_cast<char>(value)};
}

static string ErrorPacket(uint16_t sequence, const string& message = "",
                          char flags = udp::internal::kFlagNone) {
    return string{udp::internal::kIdError, flags} + PacketValue(sequence) + message;
}

static string InitPacket(uint16_t sequence, uint16_t version, uint16_t max_packet_size) {
    return string{udp::internal::kIdInitialization, udp::internal::kFlagNone} +
           PacketValue(sequence) + PacketValue(version) + PacketValue(max_packet_size);
}

static string QueryPacket(uint16_t sequence, uint16_t new_sequence) {
    return string{udp::internal::kIdDeviceQuery, udp::internal::kFlagNone} + PacketValue(sequence) +
           PacketValue(new_sequence);
}

static string QueryPacket(uint16_t sequence) {
    return string{udp::internal::kIdDeviceQuery, udp::internal::kFlagNone} + PacketValue(sequence);
}

static string FastbootPacket(uint16_t sequence, const string& data = "",
                             char flags = udp::internal::kFlagNone) {
    return string{udp::internal::kIdFastboot, flags} + PacketValue(sequence) + data;
}

void FastbootFuzzer::InvokeUdp() {
    /* Using a raw SocketMockFuzz* here because ownership shall be passed to the Transport object */
    SocketMockFuzz* udp_mock = new SocketMockFuzz;
    uint16_t starting_sequence = fdp_->ConsumeIntegral<uint16_t>();
    int32_t device_max_packet_size = fdp_->ConsumeBool() ? kValidUdpPacketSize
                                                         : fdp_->ConsumeIntegralInRange<uint16_t>(
                                                                   0, kValidUdpPacketSize - 1);
    udp_mock->ExpectSend(QueryPacket(0));
    udp_mock->AddReceive(QueryPacket(0, starting_sequence));
    udp_mock->ExpectSend(InitPacket(starting_sequence, udp::internal::kProtocolVersion,
                                    udp::internal::kHostMaxPacketSize));
    udp_mock->AddReceive(
            InitPacket(starting_sequence, udp::internal::kProtocolVersion, device_max_packet_size));

    string error;
    unique_ptr<Transport> transport = udp::internal::Connect(unique_ptr<Socket>(udp_mock), &error);
    bool is_transport_initialized = transport != nullptr && error.empty();

    if (is_transport_initialized) {
        uint16_t num_packets =
                fdp_->ConsumeIntegralInRange<uint16_t>(kMinUdpPackets, kMaxUdpPackets);

        for (uint16_t i = 0; i < num_packets; ++i) {
            string write_message = fdp_->ConsumeRandomLengthString(kMaxStringSize);
            string read_message = fdp_->ConsumeRandomLengthString(kMaxStringSize);
            if (fdp_->ConsumeBool()) {
                udp_mock->ExpectSend(FastbootPacket(i, write_message));
            } else {
                udp_mock->ExpectSend(ErrorPacket(i, write_message));
            }

            if (fdp_->ConsumeBool()) {
                udp_mock->AddReceive(FastbootPacket(i, read_message));
            } else {
                udp_mock->AddReceive(ErrorPacket(i, read_message));
            }
            transport->Write(write_message.data(), write_message.length());
            string buffer(read_message.length(), '\0');
            transport->Read(&buffer[0], buffer.length());
        }
        transport->Close();
    }
}

void FastbootFuzzer::InvokeVendorBootImgUtils(const uint8_t* data, size_t size) {
    int32_t vendor_boot_fd = open(kVendorBootFile.c_str(), O_CREAT | O_RDWR, 0644);
    if (vendor_boot_fd < 0) {
        return;
    }
    int32_t ramdisk_fd = open(kRamdiskFile.c_str(), O_CREAT | O_RDWR, 0644);
    if (ramdisk_fd < 0) {
        return;
    }
    write(vendor_boot_fd, data, size);
    write(ramdisk_fd, data, size);
    string ramdisk_name = fdp_->ConsumeBool() ? kValidRamdiskName
                                              : fdp_->ConsumeRandomLengthString(kMaxStringSize);
    string content_vendor_boot_fd = {};
    string content_ramdisk_fd = {};
    lseek(vendor_boot_fd, 0, SEEK_SET);
    lseek(ramdisk_fd, 0, SEEK_SET);
    android::base::ReadFdToString(vendor_boot_fd, &content_vendor_boot_fd);
    android::base::ReadFdToString(ramdisk_fd, &content_ramdisk_fd);
    uint64_t vendor_boot_size =
            fdp_->ConsumeBool() ? content_vendor_boot_fd.size() : fdp_->ConsumeIntegral<uint64_t>();
    uint64_t ramdisk_size =
            fdp_->ConsumeBool() ? content_ramdisk_fd.size() : fdp_->ConsumeIntegral<uint64_t>();
    (void)replace_vendor_ramdisk(vendor_boot_fd, vendor_boot_size, ramdisk_name, ramdisk_fd,
                                 ramdisk_size);
    close(vendor_boot_fd);
    close(ramdisk_fd);
}

void FastbootFuzzer::Process(const uint8_t* data, size_t size) {
    fdp_ = make_unique<FuzzedDataProvider>(data, size);
    InvokeParseApi();
    InvokeSocket();
    InvokeTcp();
    InvokeUdp();
    InvokeVendorBootImgUtils(data, size);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FastbootFuzzer fastbootFuzzer;
    fastbootFuzzer.Process(data, size);
    return 0;
}

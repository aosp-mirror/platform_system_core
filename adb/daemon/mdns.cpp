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

#include "mdns.h"
#include "adb_mdns.h"
#include "sysdeps.h"

#include <dns_sd.h>
#include <endian.h>
#include <unistd.h>

#include <chrono>
#include <mutex>
#include <random>
#include <thread>

#include <android-base/logging.h>
#include <android-base/properties.h>

using namespace std::chrono_literals;

static std::mutex& mdns_lock = *new std::mutex();
static int port;
static DNSServiceRef mdns_refs[kNumADBDNSServices];
static bool mdns_registered[kNumADBDNSServices];

void start_mdnsd() {
    if (android::base::GetProperty("init.svc.mdnsd", "") == "running") {
        return;
    }

    android::base::SetProperty("ctl.start", "mdnsd");

    if (! android::base::WaitForProperty("init.svc.mdnsd", "running", 5s)) {
        LOG(ERROR) << "Could not start mdnsd.";
    }
}

static void mdns_callback(DNSServiceRef /*ref*/,
                          DNSServiceFlags /*flags*/,
                          DNSServiceErrorType errorCode,
                          const char* /*name*/,
                          const char* /*regtype*/,
                          const char* /*domain*/,
                          void* /*context*/) {
    if (errorCode != kDNSServiceErr_NoError) {
        LOG(ERROR) << "Encountered mDNS registration error ("
            << errorCode << ").";
    }
}

static void register_mdns_service(int index, int port, const std::string service_name) {
    std::lock_guard<std::mutex> lock(mdns_lock);


    // https://tools.ietf.org/html/rfc6763
    // """
    // The format of the data within a DNS TXT record is one or more
    // strings, packed together in memory without any intervening gaps or
    // padding bytes for word alignment.
    //
    // The format of each constituent string within the DNS TXT record is a
    // single length byte, followed by 0-255 bytes of text data.
    // """
    //
    // Therefore:
    // 1. Begin with the string length
    // 2. No null termination

    std::vector<char> txtRecord;

    if (kADBDNSServiceTxtRecords[index]) {
        size_t txtRecordStringLength = strlen(kADBDNSServiceTxtRecords[index]);

        txtRecord.resize(1 +                    // length byte
                         txtRecordStringLength  // string bytes
        );

        txtRecord[0] = (char)txtRecordStringLength;
        memcpy(txtRecord.data() + 1, kADBDNSServiceTxtRecords[index], txtRecordStringLength);
    }

    auto error = DNSServiceRegister(
            &mdns_refs[index], 0, 0, service_name.c_str(), kADBDNSServices[index], nullptr, nullptr,
            htobe16((uint16_t)port), (uint16_t)txtRecord.size(),
            txtRecord.empty() ? nullptr : txtRecord.data(), mdns_callback, nullptr);

    if (error != kDNSServiceErr_NoError) {
        LOG(ERROR) << "Could not register mDNS service " << kADBDNSServices[index] << ", error ("
                   << error << ").";
        mdns_registered[index] = false;
    }

    mdns_registered[index] = true;

    LOG(INFO) << "adbd mDNS service " << kADBDNSServices[index]
              << " registered: " << mdns_registered[index];
}

static void unregister_mdns_service(int index) {
    std::lock_guard<std::mutex> lock(mdns_lock);

    if (mdns_registered[index]) {
        DNSServiceRefDeallocate(mdns_refs[index]);
    }
}

static void register_base_mdns_transport() {
    std::string hostname = "adb-";
    hostname += android::base::GetProperty("ro.serialno", "unidentified");
    register_mdns_service(kADBTransportServiceRefIndex, port, hostname);
}

static void setup_mdns_thread() {
    start_mdnsd();

    // We will now only set up the normal transport mDNS service
    // instead of registering all the adb secure mDNS services
    // in the beginning. This is to provide more privacy/security.
    register_base_mdns_transport();
}

// This also tears down any adb secure mDNS services, if they exist.
static void teardown_mdns() {
    for (int i = 0; i < kNumADBDNSServices; ++i) {
        unregister_mdns_service(i);
    }
}

static std::string RandomAlphaNumString(size_t len) {
    std::string ret;
    std::random_device rd;
    std::mt19937 mt(rd());
    // Generate values starting with zero and then up to enough to cover numeric
    // digits, small letters and capital letters (26 each).
    std::uniform_int_distribution<uint8_t> dist(0, 61);
    for (size_t i = 0; i < len; ++i) {
        uint8_t val = dist(mt);
        if (val < 10) {
            ret += '0' + val;
        } else if (val < 36) {
            ret += 'A' + (val - 10);
        } else {
            ret += 'a' + (val - 36);
        }
    }
    return ret;
}

static std::string GenerateDeviceGuid() {
    // The format is adb-<serial_no>-<six-random-alphanum>
    std::string guid = "adb-";

    std::string serial = android::base::GetProperty("ro.serialno", "");
    if (serial.empty()) {
        // Generate 16-bytes of random alphanum string
        serial = RandomAlphaNumString(16);
    }
    guid += serial + '-';
    // Random six-char suffix
    guid += RandomAlphaNumString(6);
    return guid;
}

static std::string ReadDeviceGuid() {
    std::string guid = android::base::GetProperty("persist.adb.wifi.guid", "");
    if (guid.empty()) {
        guid = GenerateDeviceGuid();
        CHECK(!guid.empty());
        android::base::SetProperty("persist.adb.wifi.guid", guid);
    }
    return guid;
}

// Public interface/////////////////////////////////////////////////////////////

void setup_mdns(int port_in) {
    // Make sure the adb wifi guid is generated.
    std::string guid = ReadDeviceGuid();
    CHECK(!guid.empty());
    port = port_in;
    std::thread(setup_mdns_thread).detach();

    // TODO: Make this more robust against a hard kill.
    atexit(teardown_mdns);
}

void register_adb_secure_connect_service(int port) {
    std::thread([port]() {
        auto service_name = ReadDeviceGuid();
        if (service_name.empty()) {
            return;
        }
        LOG(INFO) << "Registering secure_connect service (" << service_name << ")";
        register_mdns_service(kADBSecureConnectServiceRefIndex, port, service_name);
    }).detach();
}

void unregister_adb_secure_connect_service() {
    std::thread([]() { unregister_mdns_service(kADBSecureConnectServiceRefIndex); }).detach();
}

bool is_adb_secure_connect_service_registered() {
    std::lock_guard<std::mutex> lock(mdns_lock);
    return mdns_registered[kADBSecureConnectServiceRefIndex];
}

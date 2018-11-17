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

#include "adb_mdns.h"
#include "sysdeps.h"

#include <dns_sd.h>
#include <endian.h>
#include <unistd.h>

#include <chrono>
#include <mutex>
#include <thread>

#include <android-base/logging.h>
#include <android-base/properties.h>

using namespace std::chrono_literals;

static std::mutex& mdns_lock = *new std::mutex();
static int port;
static DNSServiceRef mdns_refs[kNumADBDNSServices];
static bool mdns_registered[kNumADBDNSServices];

static void start_mdns() {
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

static void setup_mdns_thread() {
    start_mdns();
    std::lock_guard<std::mutex> lock(mdns_lock);

    std::string hostname = "adb-";
    hostname += android::base::GetProperty("ro.serialno", "unidentified");

    for (int i = 0; i < kNumADBDNSServices; i++) {
        auto error = DNSServiceRegister(&mdns_refs[i], 0, 0, hostname.c_str(), kADBDNSServices[i],
                                        nullptr, nullptr, htobe16((uint16_t)port), 0, nullptr,
                                        mdns_callback, nullptr);

        if (error != kDNSServiceErr_NoError) {
            LOG(ERROR) << "Could not register mDNS service " << kADBDNSServices[i] << ", error ("
                       << error << ").";
            mdns_registered[i] = false;
        }

        mdns_registered[i] = true;
    }

    for (int i = 0; i < kNumADBDNSServices; i++) {
        LOG(INFO) << "adbd mDNS service " << kADBDNSServices[i]
                  << " registered: " << mdns_registered[i];
    }
}

static void teardown_mdns() {
    std::lock_guard<std::mutex> lock(mdns_lock);

    for (int i = 0; i < kNumADBDNSServices; ++i) {
        if (mdns_registered[i]) {
            DNSServiceRefDeallocate(mdns_refs[i]);
        }
    }
}

void setup_mdns(int port_in) {
    port = port_in;
    std::thread(setup_mdns_thread).detach();

    // TODO: Make this more robust against a hard kill.
    atexit(teardown_mdns);
}

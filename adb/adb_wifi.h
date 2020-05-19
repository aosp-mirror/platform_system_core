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

#pragma once

#include <optional>
#include <string>

#include "adb.h"

#if ADB_HOST

void adb_wifi_init(void);
void adb_wifi_pair_device(const std::string& host, const std::string& password,
                          std::string& response);
bool adb_wifi_is_known_host(const std::string& host);

std::string mdns_check();
std::string mdns_list_discovered_services();

struct MdnsInfo {
    std::string service_name;
    std::string service_type;
    std::string addr;
    uint16_t port = 0;

    MdnsInfo(std::string_view name, std::string_view type, std::string_view addr, uint16_t port)
        : service_name(name), service_type(type), addr(addr), port(port) {}
};

std::optional<MdnsInfo> mdns_get_connect_service_info(std::string_view name);
std::optional<MdnsInfo> mdns_get_pairing_service_info(std::string_view name);

#else  // !ADB_HOST

struct AdbdAuthContext;

void adbd_wifi_init(AdbdAuthContext* ctx);
void adbd_wifi_secure_connect(atransport* t);

#endif

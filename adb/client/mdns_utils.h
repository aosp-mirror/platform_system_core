/*
 * Copyright (C) 2020 The Android Open Source Project
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
#include <string_view>

#include "adb_wifi.h"

namespace mdns {

struct MdnsInstance {
    std::string instance_name;   // "my name"
    std::string service_name;    // "_adb-tls-connect"
    std::string transport_type;  // either "_tcp" or "_udp"

    MdnsInstance(std::string_view inst, std::string_view serv, std::string_view trans)
        : instance_name(inst), service_name(serv), transport_type(trans) {}
};

// This parser is based on https://tools.ietf.org/html/rfc6763#section-4.1 for
// structured service instance names, where the whole name is in the format
// <Instance>.<Service>.<Domain>.
//
// In our case, we ignore <Domain> portion of the name, which
// we always assume to be ".local", or link-local mDNS.
//
// The string can be in one of the following forms:
//   - <Instance>.<Service>.<Domain>.?
//     - e.g. "instance._service._tcp.local" (or "...local.")
//   - <Instance>.<Service>.? (must contain either "_tcp" or "_udp" at the end)
//     - e.g. "instance._service._tcp" (or "..._tcp.)
//   - <Instance> (can contain dots '.')
//     - e.g. "myname", "name.", "my.name."
//
// Returns an MdnsInstance with the appropriate fields filled in (instance name is never empty),
// otherwise returns std::nullopt.
std::optional<MdnsInstance> mdns_parse_instance_name(std::string_view name);

}  // namespace mdns

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

#include <stddef.h>
#include <stdint.h>

#include <functional>
#include <memory>
#include <string_view>
#include <vector>

#include "adb/pairing/pairing_connection.h"

typedef void (*pairing_client_result_cb)(const PeerInfo*, void*);

namespace adb {
namespace pairing {

// PairingClient is the client side of the PairingConnection protocol. It will
// attempt to connect to a PairingServer specified at |host| and |port|, and
// allocate a new PairingConnection for processing.
//
// See pairing_connection_test.cpp for example usage.
//
class PairingClient {
  public:
    using Data = std::vector<uint8_t>;

    virtual ~PairingClient() = default;

    // Starts the pairing client. This call is non-blocking. Upon completion,
    // if the pairing was successful, then |cb| will be called with the PeerInfo
    // containing the info of the trusted peer. Otherwise, |cb| will be
    // called with an empty value. Start can only be called once in the lifetime
    // of this object. |ip_addr| requires a port to be specified.
    //
    // Returns true if PairingClient was successfully started. Otherwise,
    // returns false.
    virtual bool Start(std::string_view ip_addr, pairing_client_result_cb cb, void* opaque) = 0;

    // Creates a new PairingClient instance. May return null if unable
    // to create an instance. |pswd|, |certificate|, |priv_key| and
    // |ip_addr| cannot be empty. |peer_info| must contain non-empty strings for
    // the guid and name fields.
    static std::unique_ptr<PairingClient> Create(const Data& pswd, const PeerInfo& peer_info,
                                                 const Data& certificate, const Data& priv_key);

  protected:
    PairingClient() = default;
};  // class PairingClient

}  // namespace pairing
}  // namespace adb

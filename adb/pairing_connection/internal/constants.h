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

// This file contains constants that can be used both in the pairing_connection
// code and tested in the pairing_connection_test code.
namespace adb {
namespace pairing {
namespace internal {

// The maximum number of connections the PairingServer can handle at once.
constexpr int kMaxConnections = 10;
// The maximum number of attempts the PairingServer will take before quitting.
// This is to prevent someone malicious from quickly brute-forcing every
// combination.
constexpr int kMaxPairingAttempts = 20;

}  // namespace internal
}  // namespace pairing
}  // namespace adb

// Copyright (C) 2016 The Android Open Source Project
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

#ifndef _INIT_CAPABILITIES_H
#define _INIT_CAPABILITIES_H

#include <sys/capability.h>

#include <bitset>
#include <string>
#include <type_traits>

namespace android {
namespace init {

struct CapDeleter {
    void operator()(cap_t caps) const { cap_free(caps); }
};

using CapSet = std::bitset<CAP_LAST_CAP + 1>;
using ScopedCaps = std::unique_ptr<std::remove_pointer<cap_t>::type, CapDeleter>;

int LookupCap(const std::string& cap_name);
bool CapAmbientSupported();
unsigned int GetLastValidCap();
bool SetCapsForExec(const CapSet& to_keep);
bool DropInheritableCaps();

}  // namespace init
}  // namespace android

#endif  // _INIT_CAPABILITIES_H

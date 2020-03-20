//
// Copyright (C) 2019 The Android Open Source Project
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
//

#pragma once

#include <map>
#include <set>

#include <android-base/result.h>

namespace android {
namespace init {

// this is service name -> interface declaration
//
// So, for:
//     service foo ..
//         interface aidl baz
//         interface android.hardware.foo@1.0 IFoo
//
// We have:
//     foo -> { aidl/baz, android.hardware.foo@1.0/IFoo }
using ServiceInterfacesMap = std::map<std::string, std::set<std::string>>;
android::base::Result<ServiceInterfacesMap> GetOnDeviceServiceInterfacesMap();

}  // namespace init
}  // namespace android

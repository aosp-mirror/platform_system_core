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

#include <string>

#include <android-base/logging.h>

#include "../parser.h"
#include "../service.h"
#include "../service_list.h"
#include "../service_parser.h"
#include "include/init-test-utils/service_utils.h"

namespace android {
namespace init {

android::base::Result<ServiceInterfacesMap> GetOnDeviceServiceInterfacesMap() {
    ServiceList& service_list = ServiceList::GetInstance();
    Parser parser;
    parser.AddSectionParser("service", std::make_unique<ServiceParser>(&service_list, nullptr));
    for (const auto& location : {
                 "/init.rc",
                 "/system/etc/init",
                 "/system_ext/etc/init",
                 "/product/etc/init",
                 "/odm/etc/init",
                 "/vendor/etc/init",
         }) {
        parser.ParseConfig(location);
    }

    ServiceInterfacesMap result;
    for (const auto& service : service_list) {
        // Create an entry for all services, including services that may not
        // have any declared interfaces.
        result[service->name()] = service->interfaces();
    }
    return result;
}

}  // namespace init
}  // namespace android

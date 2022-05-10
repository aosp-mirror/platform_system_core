/*
 * Copyright (C) 2021 The Android Open Source Project
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
#include "include/StatsBootstrapAtomClient.h"

#include <android/os/IStatsBootstrapAtomService.h>

#include "BootstrapClientInternal.h"

namespace android {
namespace os {
namespace stats {

bool StatsBootstrapAtomClient::reportBootstrapAtom(const StatsBootstrapAtom& atom) {
    sp<IStatsBootstrapAtomService> service =
            BootstrapClientInternal::getInstance()->getServiceNonBlocking();
    if (service == nullptr) {
        return false;
    }
    return service->reportBootstrapAtom(atom).isOk();
}

}  // namespace stats
}  // namespace os
}  // namespace android
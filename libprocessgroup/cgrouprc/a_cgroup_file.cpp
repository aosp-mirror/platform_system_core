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

#include <iterator>

#include <android-base/logging.h>
#include <android/cgrouprc.h>
#include <processgroup/util.h>

#include "cgrouprc_internal.h"

static CgroupDescriptorMap* LoadDescriptors() {
    CgroupDescriptorMap* descriptors = new CgroupDescriptorMap;
    if (!ReadDescriptors(descriptors)) {
        LOG(ERROR) << "Failed to load cgroup description file";
        return nullptr;
    }
    return descriptors;
}

static const CgroupDescriptorMap* GetInstance() {
    // Deliberately leak this object (not munmap) to avoid a race between destruction on
    // process exit and concurrent access from another thread.
    static const CgroupDescriptorMap* descriptors = LoadDescriptors();
    return descriptors;
}

uint32_t ACgroupFile_getVersion() {
    static constexpr uint32_t FILE_VERSION_1 = 1;
    auto descriptors = GetInstance();
    if (descriptors == nullptr) return 0;
    // There has only ever been one version, and there will be no more since cgroup.rc is no more
    return FILE_VERSION_1;
}

uint32_t ACgroupFile_getControllerCount() {
    auto descriptors = GetInstance();
    if (descriptors == nullptr) return 0;
    return descriptors->size();
}

const ACgroupController* ACgroupFile_getController(uint32_t index) {
    auto descriptors = GetInstance();
    if (descriptors == nullptr) return nullptr;
    CHECK(index < descriptors->size());
    // Although the object is not actually an ACgroupController object, all ACgroupController_*
    // functions implicitly convert ACgroupController* back to CgroupController* before invoking
    // member functions.
    const CgroupController* p = std::next(descriptors->begin(), index)->second.controller();
    return static_cast<const ACgroupController*>(p);
}

/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include "libdm/dm_target.h"

#include <android-base/logging.h>
#include <android-base/macros.h>

#include <libdm/dm.h>

namespace android {
namespace dm {

std::string DmTarget::Serialize() const {
    // Create a string containing a dm_target_spec, parameter data, and an
    // explicit null terminator.
    std::string data(sizeof(dm_target_spec), '\0');
    data += GetParameterString();
    data.push_back('\0');

    // The kernel expects each target to be 8-byte aligned.
    size_t padding = DM_ALIGN(data.size()) - data.size();
    for (size_t i = 0; i < padding; i++) {
        data.push_back('\0');
    }

    // Finally fill in the dm_target_spec.
    struct dm_target_spec* spec = reinterpret_cast<struct dm_target_spec*>(&data[0]);
    spec->sector_start = start();
    spec->length = size();
    strlcpy(spec->target_type, name().c_str(), sizeof(spec->target_type));
    spec->next = (uint32_t)data.size();
    return data;
}

std::string DmTargetZero::GetParameterString() const {
    // The zero target type has no additional parameters.
    return "";
}

std::string DmTargetLinear::GetParameterString() const {
    return block_device_ + " " + std::to_string(physical_sector_);
}

}  // namespace dm
}  // namespace android

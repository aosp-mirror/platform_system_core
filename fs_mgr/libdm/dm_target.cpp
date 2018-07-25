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
#include <android-base/strings.h>

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

DmTargetVerity::DmTargetVerity(uint64_t start, uint64_t length, uint32_t version,
                               const std::string& block_device, const std::string& hash_device,
                               uint32_t data_block_size, uint32_t hash_block_size,
                               uint32_t num_data_blocks, uint32_t hash_start_block,
                               const std::string& hash_algorithm, const std::string& root_digest,
                               const std::string& salt)
    : DmTarget(start, length), valid_(true) {
    base_args_ = {
            std::to_string(version),
            block_device,
            hash_device,
            std::to_string(data_block_size),
            std::to_string(hash_block_size),
            std::to_string(num_data_blocks),
            std::to_string(hash_start_block),
            hash_algorithm,
            root_digest,
            salt,
    };
}

void DmTargetVerity::UseFec(const std::string& device, uint32_t num_roots, uint32_t num_blocks,
                            uint32_t start) {
    optional_args_.emplace_back("use_fec_from_device");
    optional_args_.emplace_back(device);
    optional_args_.emplace_back("fec_roots");
    optional_args_.emplace_back(std::to_string(num_roots));
    optional_args_.emplace_back("fec_blocks");
    optional_args_.emplace_back(std::to_string(num_blocks));
    optional_args_.emplace_back("fec_start");
    optional_args_.emplace_back(std::to_string(start));
}

void DmTargetVerity::SetVerityMode(const std::string& mode) {
    if (mode != "restart_on_corruption" && mode != "ignore_corruption") {
        LOG(ERROR) << "Unknown verity mode: " << mode;
        valid_ = false;
        return;
    }
    optional_args_.emplace_back(mode);
}

void DmTargetVerity::IgnoreZeroBlocks() {
    optional_args_.emplace_back("ignore_zero_blocks");
}

std::string DmTargetVerity::GetParameterString() const {
    std::string base = android::base::Join(base_args_, " ");
    if (optional_args_.empty()) {
        return base;
    }
    std::string optional = android::base::Join(optional_args_, " ");
    return base + " " + std::to_string(optional_args_.size()) + " " + optional;
}

}  // namespace dm
}  // namespace android

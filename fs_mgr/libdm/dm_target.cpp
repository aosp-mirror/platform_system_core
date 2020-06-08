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

#include <inttypes.h>
#include <stdio.h>
#include <sys/types.h>

#include <android-base/logging.h>
#include <android-base/macros.h>
#include <android-base/parseint.h>
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
    snprintf(spec->target_type, sizeof(spec->target_type), "%s", name().c_str());
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

std::string DmTargetAndroidVerity::GetParameterString() const {
    return keyid_ + " " + block_device_;
}

std::string DmTargetBow::GetParameterString() const {
    if (!block_size_) return target_string_;
    return target_string_ + " 1 block_size:" + std::to_string(block_size_);
}

std::string DmTargetSnapshot::name() const {
    if (mode_ == SnapshotStorageMode::Merge) {
        return "snapshot-merge";
    }
    return "snapshot";
}

std::string DmTargetSnapshot::GetParameterString() const {
    std::string mode;
    switch (mode_) {
        case SnapshotStorageMode::Persistent:
        case SnapshotStorageMode::Merge:
            // Note: "O" lets us query for overflow in the status message. This
            // is only supported on kernels 4.4+. On earlier kernels, an overflow
            // will be reported as "Invalid" in the status string.
            mode = "P";
            if (ReportsOverflow(name())) {
                mode += "O";
            }
            break;
        case SnapshotStorageMode::Transient:
            mode = "N";
            break;
        default:
            LOG(ERROR) << "DmTargetSnapshot unknown mode";
            break;
    }
    return base_device_ + " " + cow_device_ + " " + mode + " " + std::to_string(chunk_size_);
}

// Computes the percentage of complition for snapshot status.
// @sectors_initial is the number of sectors_allocated stored right before
// starting the merge.
double DmTargetSnapshot::MergePercent(const DmTargetSnapshot::Status& status,
                                      uint64_t sectors_initial) {
    uint64_t s = status.sectors_allocated;
    uint64_t t = status.total_sectors;
    uint64_t m = status.metadata_sectors;
    uint64_t i = sectors_initial == 0 ? t : sectors_initial;

    if (t <= s || i <= s) {
        return 0.0;
    }
    if (s == 0 || t == 0 || s <= m) {
        return 100.0;
    }
    return 100.0 / (i - m) * (i - s);
}

bool DmTargetSnapshot::ReportsOverflow(const std::string& target_type) {
    DeviceMapper& dm = DeviceMapper::Instance();
    DmTargetTypeInfo info;
    if (!dm.GetTargetByName(target_type, &info)) {
        return false;
    }
    if (target_type == "snapshot") {
        return info.IsAtLeast(1, 15, 0);
    }
    if (target_type == "snapshot-merge") {
        return info.IsAtLeast(1, 4, 0);
    }
    return false;
}

bool DmTargetSnapshot::ParseStatusText(const std::string& text, Status* status) {
    // Try to parse the line as it should be
    int args = sscanf(text.c_str(), "%" PRIu64 "/%" PRIu64 " %" PRIu64, &status->sectors_allocated,
                      &status->total_sectors, &status->metadata_sectors);
    if (args == 3) {
        return true;
    }
    auto sections = android::base::Split(text, " ");
    if (sections.size() == 0) {
        LOG(ERROR) << "could not parse empty status";
        return false;
    }
    // Error codes are: "Invalid", "Overflow" and "Merge failed"
    if (sections.size() == 1) {
        if (text == "Invalid" || text == "Overflow") {
            status->error = text;
            return true;
        }
    } else if (sections.size() == 2 && text == "Merge failed") {
        status->error = text;
        return true;
    }
    LOG(ERROR) << "could not parse snapshot status: wrong format";
    return false;
}

bool DmTargetSnapshot::GetDevicesFromParams(const std::string& params, std::string* base_device,
                                            std::string* cow_device) {
    auto pieces = android::base::Split(params, " ");
    if (pieces.size() < 2) {
        LOG(ERROR) << "Parameter string is invalid: " << params;
        return false;
    }
    *base_device = pieces[0];
    *cow_device = pieces[1];
    return true;
}

std::string DmTargetCrypt::GetParameterString() const {
    std::vector<std::string> argv = {
            cipher_,
            key_,
            std::to_string(iv_sector_offset_),
            device_,
            std::to_string(device_sector_),
    };

    std::vector<std::string> extra_argv;
    if (allow_discards_) extra_argv.emplace_back("allow_discards");
    if (allow_encrypt_override_) extra_argv.emplace_back("allow_encrypt_override");
    if (iv_large_sectors_) extra_argv.emplace_back("iv_large_sectors");
    if (sector_size_) extra_argv.emplace_back("sector_size:" + std::to_string(sector_size_));

    if (!extra_argv.empty()) argv.emplace_back(std::to_string(extra_argv.size()));

    argv.insert(argv.end(), extra_argv.begin(), extra_argv.end());
    return android::base::Join(argv, " ");
}

bool DmTargetDefaultKey::Valid() const {
    if (!use_legacy_options_format_ && !set_dun_) return false;
    return true;
}

std::string DmTargetDefaultKey::GetParameterString() const {
    std::vector<std::string> argv;
    argv.emplace_back(cipher_);
    argv.emplace_back(key_);
    if (!use_legacy_options_format_) {
        argv.emplace_back("0");  // iv_offset
    }
    argv.emplace_back(blockdev_);
    argv.push_back(std::to_string(start_sector_));
    std::vector<std::string> extra_argv;
    if (use_legacy_options_format_) {
        if (set_dun_) {  // v2 always sets the DUN.
            extra_argv.emplace_back("set_dun");
        }
    } else {
        extra_argv.emplace_back("allow_discards");
        extra_argv.emplace_back("sector_size:4096");
        extra_argv.emplace_back("iv_large_sectors");
        if (is_hw_wrapped_) extra_argv.emplace_back("wrappedkey_v0");
    }
    if (!extra_argv.empty()) {
        argv.emplace_back(std::to_string(extra_argv.size()));
        argv.insert(argv.end(), extra_argv.begin(), extra_argv.end());
    }
    return android::base::Join(argv, " ");
}

}  // namespace dm
}  // namespace android

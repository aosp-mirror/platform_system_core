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

#include "fs_avb/types.h"

namespace android {
namespace fs_mgr {

// Helper functions to print enum class VBMetaVerifyResult.
const char* VBMetaVerifyResultToString(VBMetaVerifyResult result) {
    // clang-format off
    static const char* const name[] = {
        "ResultSuccess",
        "ResultError",
        "ResultErrorVerification",
        "ResultUnknown",
    };
    // clang-format on

    uint32_t index = static_cast<uint32_t>(result);
    uint32_t unknown_index = sizeof(name) / sizeof(char*) - 1;
    if (index >= unknown_index) {
        index = unknown_index;
    }

    return name[index];
}

std::ostream& operator<<(std::ostream& os, VBMetaVerifyResult result) {
    os << VBMetaVerifyResultToString(result);
    return os;
}

// Helper functions to dump enum class AvbHandleStatus.
const char* AvbHandleStatusToString(AvbHandleStatus status) {
    // clang-format off
    static const char* const name[] = {
        "Success",
        "Uninitialized",
        "HashtreeDisabled",
        "VerificationDisabled",
        "VerificationError",
        "Unknown",
    };
    // clang-format on

    uint32_t index = static_cast<uint32_t>(status);
    uint32_t unknown_index = sizeof(name) / sizeof(char*) - 1;
    if (index >= unknown_index) {
        index = unknown_index;
    }

    return name[index];
}

std::ostream& operator<<(std::ostream& os, AvbHandleStatus status) {
    os << AvbHandleStatusToString(status);
    return os;
}

// class VBMetaData
// ----------------
std::unique_ptr<AvbVBMetaImageHeader> VBMetaData::GetVBMetaHeader(bool update_vbmeta_size) {
    auto vbmeta_header = std::make_unique<AvbVBMetaImageHeader>();

    if (!vbmeta_header) return nullptr;

    /* Byteswap the header. */
    avb_vbmeta_image_header_to_host_byte_order((AvbVBMetaImageHeader*)vbmeta_ptr_.get(),
                                               vbmeta_header.get());
    if (update_vbmeta_size) {
        vbmeta_size_ = sizeof(AvbVBMetaImageHeader) +
                       vbmeta_header->authentication_data_block_size +
                       vbmeta_header->auxiliary_data_block_size;
    }

    return vbmeta_header;
}

}  // namespace fs_mgr
}  // namespace android

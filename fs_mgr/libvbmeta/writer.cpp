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

#include "writer.h"

#include <android-base/file.h>

#include "utility.h"

using android::base::ErrnoError;
using android::base::Result;

namespace android {
namespace fs_mgr {

std::string SerializeVBMetaTable(const VBMetaTable& input) {
    std::string table;
    table.append(reinterpret_cast<const char*>(&input.header), SUPER_VBMETA_HEADER_SIZE);

    for (const auto& desc : input.descriptors) {
        table.append(reinterpret_cast<const char*>(&desc), SUPER_VBMETA_DESCRIPTOR_SIZE);
        table.append(desc.vbmeta_name);
    }

    // Ensure the size of vbmeta table is SUPER_VBMETA_TABLE_MAX_SIZE
    table.resize(SUPER_VBMETA_TABLE_MAX_SIZE, '\0');

    return table;
}

Result<void> WritePrimaryVBMetaTable(int fd, const std::string& table) {
    const uint64_t offset = PRIMARY_SUPER_VBMETA_TABLE_OFFSET;
    if (lseek(fd, offset, SEEK_SET) < 0) {
        return ErrnoError() << __PRETTY_FUNCTION__ << " lseek failed";
    }

    if (!android::base::WriteFully(fd, table.data(), table.size())) {
        return ErrnoError() << "Failed to write primary vbmeta table at offset " << offset;
    }
    return {};
}

Result<void> WriteBackupVBMetaTable(int fd, const std::string& table) {
    const uint64_t offset = BACKUP_SUPER_VBMETA_TABLE_OFFSET;
    if (lseek(fd, offset, SEEK_SET) < 0) {
        return ErrnoError() << __PRETTY_FUNCTION__ << " lseek failed";
    }

    if (!android::base::WriteFully(fd, table.data(), table.size())) {
        return ErrnoError() << "Failed to write backup vbmeta table at offset " << offset;
    }
    return {};
}

Result<void> WriteVBMetaImage(int fd, const uint8_t slot_number, const std::string& vbmeta_image) {
    const uint64_t offset = IndexOffset(slot_number);
    if (lseek(fd, offset, SEEK_SET) < 0) {
        return ErrnoError() << __PRETTY_FUNCTION__ << " lseek failed";
    }

    if (!android::base::WriteFully(fd, vbmeta_image.data(), vbmeta_image.size())) {
        return ErrnoError() << "Failed to write vbmeta image at offset " << offset;
    }
    return {};
}

}  // namespace fs_mgr
}  // namespace android
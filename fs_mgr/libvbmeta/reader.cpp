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

#include "reader.h"

#include <android-base/file.h>

using android::base::ErrnoError;
using android::base::Error;
using android::base::Result;

namespace android {
namespace fs_mgr {

Result<void> LoadAndVerifySuperVBMetaHeader(const void* buffer, SuperVBMetaHeader* header) {
    memcpy(header, buffer, sizeof(*header));

    // Do basic validation of super vbmeta.
    if (header->magic != SUPER_VBMETA_MAGIC) {
        return Error() << "Super VBMeta has invalid magic value";
    }

    // Check that the version is compatible.
    if (header->major_version != SUPER_VBMETA_MAJOR_VERSION ||
        header->minor_version > SUPER_VBMETA_MINOR_VERSION) {
        return Error() << "Super VBMeta has incompatible version";
    }
    return {};
}

void LoadVBMetaDescriptors(const void* buffer, uint32_t size,
                           std::vector<InternalVBMetaDescriptor>* descriptors) {
    for (int p = 0; p < size;) {
        InternalVBMetaDescriptor descriptor;
        memcpy(&descriptor, (char*)buffer + p, SUPER_VBMETA_DESCRIPTOR_SIZE);
        p += SUPER_VBMETA_DESCRIPTOR_SIZE;

        descriptor.vbmeta_name = std::string((char*)buffer + p, descriptor.vbmeta_name_length);
        p += descriptor.vbmeta_name_length;

        descriptors->emplace_back(std::move(descriptor));
    }
}

Result<void> ReadVBMetaTable(int fd, uint64_t offset, VBMetaTable* table) {
    std::unique_ptr<uint8_t[]> header_buffer =
            std::make_unique<uint8_t[]>(SUPER_VBMETA_HEADER_SIZE);
    if (!android::base::ReadFullyAtOffset(fd, header_buffer.get(), SUPER_VBMETA_HEADER_SIZE,
                                          offset)) {
        return ErrnoError() << "Couldn't read super vbmeta header at offset " << offset;
    }

    Result<void> rv_header = LoadAndVerifySuperVBMetaHeader(header_buffer.get(), &table->header);
    if (!rv_header.ok()) {
        return rv_header;
    }

    const uint64_t descriptors_offset = offset + table->header.header_size;
    std::unique_ptr<uint8_t[]> descriptors_buffer =
            std::make_unique<uint8_t[]>(table->header.descriptors_size);
    if (!android::base::ReadFullyAtOffset(fd, descriptors_buffer.get(),
                                          table->header.descriptors_size, descriptors_offset)) {
        return ErrnoError() << "Couldn't read super vbmeta descriptors at offset "
                            << descriptors_offset;
    }

    LoadVBMetaDescriptors(descriptors_buffer.get(), table->header.descriptors_size,
                          &table->descriptors);
    return {};
}

Result<void> ReadPrimaryVBMetaTable(int fd, VBMetaTable* table) {
    uint64_t offset = PRIMARY_SUPER_VBMETA_TABLE_OFFSET;
    return ReadVBMetaTable(fd, offset, table);
}

Result<void> ReadBackupVBMetaTable(int fd, VBMetaTable* table) {
    uint64_t offset = BACKUP_SUPER_VBMETA_TABLE_OFFSET;
    return ReadVBMetaTable(fd, offset, table);
}

Result<std::string> ReadVBMetaImage(int fd, int slot) {
    const uint64_t offset = 2 * SUPER_VBMETA_TABLE_MAX_SIZE + slot * VBMETA_IMAGE_MAX_SIZE;
    std::unique_ptr<uint8_t[]> buffer = std::make_unique<uint8_t[]>(VBMETA_IMAGE_MAX_SIZE);
    if (!android::base::ReadFullyAtOffset(fd, buffer.get(), VBMETA_IMAGE_MAX_SIZE, offset)) {
        return ErrnoError() << "Couldn't read vbmeta image at offset " << offset;
    }
    return std::string(reinterpret_cast<char*>(buffer.get()), VBMETA_IMAGE_MAX_SIZE);
}

Result<void> ValidateVBMetaImage(int super_vbmeta_fd, int vbmeta_index,
                                 const std::string& vbmeta_image) {
    Result<std::string> content = ReadVBMetaImage(super_vbmeta_fd, vbmeta_index);
    if (!content.ok()) {
        return content.error();
    }

    if (vbmeta_image != content.value()) {
        return Error() << "VBMeta Image in Super VBMeta differ from the original one.";
    }
    return {};
}

}  // namespace fs_mgr
}  // namespace android

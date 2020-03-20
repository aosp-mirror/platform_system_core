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

#include "builder.h"

#include <android-base/file.h>
#include <openssl/sha.h>

#include "reader.h"
#include "utility.h"
#include "writer.h"

using android::base::ErrnoError;
using android::base::Error;
using android::base::Result;
using android::base::unique_fd;

namespace android {
namespace fs_mgr {

SuperVBMetaBuilder::SuperVBMetaBuilder() {}

SuperVBMetaBuilder::SuperVBMetaBuilder(const int super_vbmeta_fd,
                                       const std::map<std::string, std::string>& images_path)
    : super_vbmeta_fd_(super_vbmeta_fd), images_path_(images_path) {}

Result<void> SuperVBMetaBuilder::Build() {
    for (const auto& [vbmeta_name, file_path] : images_path_) {
        Result<std::string> content = ReadVBMetaImageFromFile(file_path);
        if (!content.ok()) {
            return content.error();
        }

        Result<uint8_t> vbmeta_index = AddVBMetaImage(vbmeta_name);
        if (!vbmeta_index.ok()) {
            return vbmeta_index.error();
        }

        Result<void> rv_export_vbmeta_image =
                ExportVBMetaImageToFile(vbmeta_index.value(), content.value());
        if (!rv_export_vbmeta_image.ok()) {
            return rv_export_vbmeta_image;
        }
    }
    return {};
}

Result<std::string> SuperVBMetaBuilder::ReadVBMetaImageFromFile(const std::string& file) {
    unique_fd source_fd(TEMP_FAILURE_RETRY(open(file.c_str(), O_RDONLY | O_CLOEXEC)));
    if (source_fd < 0) {
        return ErrnoError() << "Couldn't open vbmeta image file " << file;
    }

    Result<uint64_t> file_size = GetFileSize(source_fd);
    if (!file_size.ok()) {
        return file_size.error();
    }

    if (file_size.value() > VBMETA_IMAGE_MAX_SIZE) {
        return Error() << "vbmeta image file size " << file_size.value() << " is too large";
    }

    std::unique_ptr<uint8_t[]> buffer = std::make_unique<uint8_t[]>(VBMETA_IMAGE_MAX_SIZE);
    if (!android::base::ReadFully(source_fd, buffer.get(), file_size.value())) {
        return ErrnoError() << "Couldn't read vbmeta image file " << file;
    }

    return std::string(reinterpret_cast<const char*>(buffer.get()), VBMETA_IMAGE_MAX_SIZE);
}

Result<uint8_t> SuperVBMetaBuilder::GetEmptySlot() {
    for (uint8_t i = 0; i < VBMETA_IMAGE_MAX_NUM; ++i) {
        if ((table_.header.in_use & (1 << i)) == 0) return i;
    }
    return Error() << "There isn't empty slot in super vbmeta";
}

Result<uint8_t> SuperVBMetaBuilder::AddVBMetaImage(const std::string& vbmeta_name) {
    auto desc = std::find_if(
            table_.descriptors.begin(), table_.descriptors.end(),
            [&vbmeta_name](const auto& entry) { return entry.vbmeta_name == vbmeta_name; });

    uint8_t slot_number = 0;
    if (desc != table_.descriptors.end()) {
        slot_number = desc->vbmeta_index;
    } else {
        Result<uint8_t> new_slot = GetEmptySlot();
        if (!new_slot.ok()) {
            return new_slot;
        }
        slot_number = new_slot.value();

        // insert new descriptor into table
        InternalVBMetaDescriptor new_desc;
        new_desc.vbmeta_index = slot_number;
        new_desc.vbmeta_name_length = vbmeta_name.length();
        new_desc.vbmeta_name = vbmeta_name;
        memset(new_desc.reserved, 0, sizeof(new_desc.reserved));
        table_.descriptors.emplace_back(std::move(new_desc));

        // mark slot as in use
        table_.header.in_use |= (1 << slot_number);
    }

    return slot_number;
}

void SuperVBMetaBuilder::DeleteVBMetaImage(const std::string& vbmeta_name) {
    auto desc = std::find_if(
            table_.descriptors.begin(), table_.descriptors.end(),
            [&vbmeta_name](const auto& entry) { return entry.vbmeta_name == vbmeta_name; });

    if (desc != table_.descriptors.end()) {
        // mark slot as not in use
        table_.header.in_use &= ~(1 << desc->vbmeta_index);

        // erase descriptor in table
        table_.descriptors.erase(desc);
    }
}

std::unique_ptr<VBMetaTable> SuperVBMetaBuilder::ExportVBMetaTable() {
    // calculate descriptors size
    uint32_t descriptors_size = 0;
    for (const auto& desc : table_.descriptors) {
        descriptors_size += SUPER_VBMETA_DESCRIPTOR_SIZE + desc.vbmeta_name_length * sizeof(char);
    }

    // export header
    table_.header.magic = SUPER_VBMETA_MAGIC;
    table_.header.major_version = SUPER_VBMETA_MAJOR_VERSION;
    table_.header.minor_version = SUPER_VBMETA_MINOR_VERSION;
    table_.header.header_size = SUPER_VBMETA_HEADER_SIZE;
    table_.header.total_size = SUPER_VBMETA_HEADER_SIZE + descriptors_size;
    memset(table_.header.checksum, 0, sizeof(table_.header.checksum));
    table_.header.descriptors_size = descriptors_size;
    memset(table_.header.reserved, 0, sizeof(table_.header.reserved));
    std::string serialized_table = SerializeVBMetaTable(table_);
    ::SHA256(reinterpret_cast<const uint8_t*>(serialized_table.c_str()), table_.header.total_size,
             &table_.header.checksum[0]);

    return std::make_unique<VBMetaTable>(table_);
}

Result<void> SuperVBMetaBuilder::ExportVBMetaTableToFile() {
    std::unique_ptr<VBMetaTable> table = ExportVBMetaTable();

    std::string serialized_table = SerializeVBMetaTable(*table);

    android::base::Result<void> rv_write_primary_vbmeta_table =
            WritePrimaryVBMetaTable(super_vbmeta_fd_, serialized_table);
    if (!rv_write_primary_vbmeta_table.ok()) {
        return rv_write_primary_vbmeta_table;
    }

    android::base::Result<void> rv_write_backup_vbmeta_table =
            WriteBackupVBMetaTable(super_vbmeta_fd_, serialized_table);
    return rv_write_backup_vbmeta_table;
}

Result<void> SuperVBMetaBuilder::ExportVBMetaImageToFile(const uint8_t vbmeta_index,
                                                         const std::string& vbmeta_image) {
    Result<void> rv_write_vbmeta_image =
            WriteVBMetaImage(super_vbmeta_fd_, vbmeta_index, vbmeta_image);
    if (!rv_write_vbmeta_image.ok()) {
        return rv_write_vbmeta_image;
    }

    Result<void> rv_validate_vbmeta_image =
            ValidateVBMetaImage(super_vbmeta_fd_, vbmeta_index, vbmeta_image);
    return rv_validate_vbmeta_image;
}

bool WriteToSuperVBMetaFile(const std::string& super_vbmeta_file,
                            const std::map<std::string, std::string>& images_path) {
    unique_fd super_vbmeta_fd(TEMP_FAILURE_RETRY(
            open(super_vbmeta_file.c_str(), O_CREAT | O_RDWR | O_TRUNC | O_CLOEXEC, 0644)));
    if (super_vbmeta_fd < 0) {
        PERROR << "Couldn't open super vbmeta file " << super_vbmeta_file;
        return false;
    }

    SuperVBMetaBuilder builder(super_vbmeta_fd, images_path);

    Result<void> rv_build = builder.Build();
    if (!rv_build.ok()) {
        LERROR << rv_build.error();
        return false;
    }

    Result<void> rv_export = builder.ExportVBMetaTableToFile();
    if (!rv_export.ok()) {
        LERROR << rv_export.error();
        return false;
    }

    return true;
}

}  // namespace fs_mgr
}  // namespace android

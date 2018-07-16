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

#include "images.h"

#include <android-base/file.h>
#include <android-base/unique_fd.h>

#include "reader.h"
#include "utility.h"
#include "writer.h"

namespace android {
namespace fs_mgr {

std::unique_ptr<LpMetadata> ReadFromImageFile(int fd) {
    LpMetadataGeometry geometry;
    if (!ReadLogicalPartitionGeometry(fd, &geometry)) {
        return nullptr;
    }
    if (SeekFile64(fd, LP_METADATA_GEOMETRY_SIZE, SEEK_SET) < 0) {
        PERROR << __PRETTY_FUNCTION__ << "lseek failed: offset " << LP_METADATA_GEOMETRY_SIZE;
        return nullptr;
    }
    std::unique_ptr<LpMetadata> metadata = ParseMetadata(fd);
    if (!metadata) {
        return nullptr;
    }
    metadata->geometry = geometry;
    return metadata;
}

std::unique_ptr<LpMetadata> ReadFromImageFile(const char* file) {
    android::base::unique_fd fd(open(file, O_RDONLY));
    if (fd < 0) {
        PERROR << __PRETTY_FUNCTION__ << "open failed: " << file;
        return nullptr;
    }
    return ReadFromImageFile(fd);
}

bool WriteToImageFile(int fd, const LpMetadata& input) {
    std::string geometry = SerializeGeometry(input.geometry);
    std::string padding(LP_METADATA_GEOMETRY_SIZE - geometry.size(), '\0');
    std::string metadata = SerializeMetadata(input);

    std::string everything = geometry + padding + metadata;

    if (!android::base::WriteFully(fd, everything.data(), everything.size())) {
        PERROR << __PRETTY_FUNCTION__ << "write " << everything.size() << " bytes failed";
        return false;
    }
    return true;
}

bool WriteToImageFile(const char* file, const LpMetadata& input) {
    android::base::unique_fd fd(open(file, O_CREAT | O_RDWR | O_TRUNC, 0644));
    if (fd < 0) {
        PERROR << __PRETTY_FUNCTION__ << "open failed: " << file;
        return false;
    }
    return WriteToImageFile(fd, input);
}

}  // namespace fs_mgr
}  // namespace android

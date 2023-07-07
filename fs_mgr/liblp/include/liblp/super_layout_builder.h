//
// Copyright (C) 2023 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
#pragma once

#include <stdint.h>

#include <memory>
#include <ostream>
#include <string>
#include <unordered_map>
#include <utility>

#include <android-base/unique_fd.h>
#include <liblp/builder.h>

namespace android {
namespace fs_mgr {

struct SuperImageExtent {
    enum class Type { INVALID, DATA, PARTITION, ZERO, DONTCARE };

    SuperImageExtent(const SuperImageExtent& other) = default;
    SuperImageExtent(SuperImageExtent&& other) = default;
    SuperImageExtent(uint64_t offset, uint64_t size, Type type)
        : offset(offset), size(size), type(type) {}

    SuperImageExtent(uint64_t offset, std::shared_ptr<std::string> blob)
        : SuperImageExtent(offset, blob->size(), Type::DATA) {
        this->blob = blob;
    }

    SuperImageExtent(uint64_t offset, uint64_t size, const std::string& image_name,
                     uint64_t image_offset)
        : SuperImageExtent(offset, size, Type::PARTITION) {
        this->image_name = image_name;
        this->image_offset = image_offset;
    }

    SuperImageExtent& operator=(const SuperImageExtent& other) = default;
    SuperImageExtent& operator=(SuperImageExtent&& other) = default;

    bool operator<(const SuperImageExtent& other) const { return offset < other.offset; }
    bool operator==(const SuperImageExtent& other) const;

    // Location, size, and type of the extent.
    uint64_t offset = 0;
    uint64_t size = 0;
    Type type = Type::INVALID;

    // If type == DATA, this contains the bytes to write.
    std::shared_ptr<std::string> blob;
    // If type == PARTITION, this contains the partition image name and
    // offset within that file.
    std::string image_name;
    uint64_t image_offset = 0;
};

// The SuperLayoutBuilder allows building a sparse view of a super image. This
// is useful for efficient flashing, eg to bypass fastbootd and directly flash
// super without physically building and storing the image.
class SuperLayoutBuilder final {
  public:
    // Open a super_empty.img, return false on failure. This must be called to
    // initialize the tool. If it returns false, either the image failed to
    // parse, or the tool is not compatible with how the device is configured
    // (in which case fastbootd should be preferred).
    [[nodiscard]] bool Open(android::base::borrowed_fd fd);
    [[nodiscard]] bool Open(const void* data, size_t bytes);
    [[nodiscard]] bool Open(const LpMetadata& metadata);

    // Add a partition's image and size to the work list. If false is returned,
    // there was either a duplicate partition or not enough space in super.
    bool AddPartition(const std::string& partition_name, const std::string& image_name,
                      uint64_t partition_size);

    // Return the list of extents describing the super image. If this list is
    // empty, then there was an unrecoverable error in building the list.
    std::vector<SuperImageExtent> GetImageLayout();

    // Return the current metadata.
    std::unique_ptr<LpMetadata> Export() const { return builder_->Export(); }

  private:
    std::unique_ptr<MetadataBuilder> builder_;
    std::unordered_map<std::string, std::string> image_map_;
};

std::ostream& operator<<(std::ostream& stream, const SuperImageExtent& extent);

}  // namespace fs_mgr
}  // namespace android

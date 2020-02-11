//
// Copyright (C) 2019 The Android Open Source Project
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

#include <stdint.h>

#include <memory>
#include <string>

#include <libfiemap/split_fiemap_writer.h>
#include <liblp/liblp.h>

namespace android {
namespace fiemap {

bool MetadataExists(const std::string& metadata_dir);
std::unique_ptr<android::fs_mgr::LpMetadata> OpenMetadata(const std::string& metadata_dir);
bool UpdateMetadata(const std::string& metadata_dir, const std::string& partition_name,
                    SplitFiemap* file, uint64_t partition_size, bool readonly);
bool AddAttributes(const std::string& metadata_dir, const std::string& partition_name,
                   uint32_t attributes);
bool RemoveImageMetadata(const std::string& metadata_dir, const std::string& partition_name);
bool RemoveAllMetadata(const std::string& dir);

}  // namespace fiemap
}  // namespace android

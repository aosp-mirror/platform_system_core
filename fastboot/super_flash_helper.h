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

#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include <android-base/unique_fd.h>
#include <liblp/liblp.h>
#include <liblp/super_layout_builder.h>

#include "util.h"

class SuperFlashHelper final {
  public:
    explicit SuperFlashHelper(const ImageSource& source);

    bool Open(android::base::borrowed_fd fd);
    bool IncludeInSuper(const std::string& partition);
    bool AddPartition(const std::string& partition, const std::string& image_name, bool optional);

    // Note: the SparsePtr if non-null should not outlive SuperFlashHelper, since
    // it depends on open fds and data pointers.
    SparsePtr GetSparseLayout();

    bool WillFlash(const std::string& partition) const {
        return will_flash_.find(partition) != will_flash_.end();
    }

  private:
    const ImageSource& source_;
    android::fs_mgr::SuperLayoutBuilder builder_;
    std::unique_ptr<android::fs_mgr::LpMetadata> base_metadata_;
    std::vector<android::fs_mgr::SuperImageExtent> extents_;

    // Cache open image fds. This keeps them alive while we flash the sparse
    // file.
    std::unordered_map<std::string, android::base::unique_fd> image_fds_;
    std::unordered_set<std::string> will_flash_;
};

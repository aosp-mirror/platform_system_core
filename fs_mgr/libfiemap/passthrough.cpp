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

#include <libfiemap/image_manager.h>

namespace android {
namespace fiemap {

std::unique_ptr<IImageManager> IImageManager::Open(const std::string& dir_prefix,
                                                   const std::chrono::milliseconds& timeout_ms) {
    (void)timeout_ms;
    return ImageManager::Open(dir_prefix);
}

}  // namespace fiemap
}  // namespace android

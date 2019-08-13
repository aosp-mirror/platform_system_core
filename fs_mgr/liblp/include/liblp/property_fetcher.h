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

#pragma once

#include <memory>

namespace android {
namespace fs_mgr {

class IPropertyFetcher {
  public:
    virtual ~IPropertyFetcher() = default;
    virtual std::string GetProperty(const std::string& key, const std::string& defaultValue) = 0;
    virtual bool GetBoolProperty(const std::string& key, bool defaultValue) = 0;

    static IPropertyFetcher* GetInstance();
    static void OverrideForTesting(std::unique_ptr<IPropertyFetcher>&&);
};

class PropertyFetcher : public IPropertyFetcher {
  public:
    ~PropertyFetcher() = default;
    std::string GetProperty(const std::string& key, const std::string& defaultValue) override;
    bool GetBoolProperty(const std::string& key, bool defaultValue) override;
};

}  // namespace fs_mgr
}  // namespace android

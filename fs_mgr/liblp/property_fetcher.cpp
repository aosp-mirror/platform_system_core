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

#include "liblp/property_fetcher.h"

#include <memory>

#include <android-base/properties.h>

namespace android {
namespace fs_mgr {

std::string PropertyFetcher::GetProperty(const std::string& key, const std::string& default_value) {
    return android::base::GetProperty(key, default_value);
}

bool PropertyFetcher::GetBoolProperty(const std::string& key, bool default_value) {
    return android::base::GetBoolProperty(key, default_value);
}

static std::unique_ptr<IPropertyFetcher>* GetInstanceAllocation() {
    static std::unique_ptr<IPropertyFetcher> instance = std::make_unique<PropertyFetcher>();
    return &instance;
}

IPropertyFetcher* IPropertyFetcher::GetInstance() {
    return GetInstanceAllocation()->get();
}

void IPropertyFetcher::OverrideForTesting(std::unique_ptr<IPropertyFetcher>&& fetcher) {
    GetInstanceAllocation()->swap(fetcher);
    fetcher.reset();
}

}  // namespace fs_mgr
}  // namespace android

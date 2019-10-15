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

#pragma once

#include <string>

#include <android-base/macros.h>

namespace android {
namespace snapshot {

// An abstract "device" that will be cleaned up (unmapped, unmounted, etc.) upon
// destruction.
struct AutoDevice {
    virtual ~AutoDevice(){};
    void Release();

    bool HasDevice() const { return !name_.empty(); }

  protected:
    AutoDevice(const std::string& name) : name_(name) {}
    std::string name_;

  private:
    DISALLOW_COPY_AND_ASSIGN(AutoDevice);
    AutoDevice(AutoDevice&& other) = delete;
};

}  // namespace snapshot
}  // namespace android

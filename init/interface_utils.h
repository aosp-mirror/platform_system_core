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

#pragma once

#include <map>
#include <set>
#include <string>

#include <hidl-util/FQName.h>

#include "result.h"

namespace android {
namespace init {

using InterfaceInheritanceHierarchyMap = std::map<android::FQName, std::set<android::FQName>>;

// For the given set of interfaces / interface instances, checks that each
// interface's hierarchy of inherited interfaces is also included in the given
// interface set. Uses the provided hierarchy data.
Result<void> CheckInterfaceInheritanceHierarchy(const std::set<std::string>& instances,
                                                const InterfaceInheritanceHierarchyMap& hierarchy);

// Saves the set of known interfaces using the provided HIDL interface
// inheritance hierarchy.
void SetKnownInterfaces(const InterfaceInheritanceHierarchyMap& hierarchy);

// Checks if the provided interface is in the set of known interfaces. Returns
// an empty Result if present, otherwise an Error.
Result<void> IsKnownInterface(const std::string& instance);
Result<void> IsKnownInterface(const FQName& intf);

}  // namespace init
}  // namespace android

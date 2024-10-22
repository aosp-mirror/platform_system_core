/*
 * Copyright (C) 2024 The Android Open Source Project
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
#include <string>

#include "cgroup_descriptor.h"

// Duplicated from cgrouprc.h. Don't depend on libcgrouprc here.
#define CGROUPRC_CONTROLLER_FLAG_MOUNTED 0x1
#define CGROUPRC_CONTROLLER_FLAG_NEEDS_ACTIVATION 0x2
#define CGROUPRC_CONTROLLER_FLAG_OPTIONAL 0x4

unsigned int GetCgroupDepth(const std::string& controller_root, const std::string& cgroup_path);

using CgroupControllerName = std::string;
using CgroupDescriptorMap = std::map<CgroupControllerName, CgroupDescriptor>;
bool ReadDescriptors(CgroupDescriptorMap* descriptors);

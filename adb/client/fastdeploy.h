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

#pragma once

#include "adb_unique_fd.h"

#include "fastdeploy/proto/ApkEntry.pb.h"

#include <optional>
#include <string>

enum FastDeploy_AgentUpdateStrategy {
    FastDeploy_AgentUpdateAlways,
    FastDeploy_AgentUpdateNewerTimeStamp,
    FastDeploy_AgentUpdateDifferentVersion
};

void fastdeploy_set_agent_update_strategy(FastDeploy_AgentUpdateStrategy agent_update_strategy);
int get_device_api_level();

std::optional<com::android::fastdeploy::APKMetaData> extract_metadata(const char* apk_path);
unique_fd install_patch(int argc, const char** argv);
unique_fd apply_patch_on_device(const char* output_path);
int stream_patch(const char* apk_path, com::android::fastdeploy::APKMetaData metadata,
                 unique_fd patch_fd);

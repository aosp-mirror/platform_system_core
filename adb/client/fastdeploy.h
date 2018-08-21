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

#include "adb.h"

typedef enum EFastDeploy_AgentUpdateStrategy {
    FastDeploy_AgentUpdateAlways,
    FastDeploy_AgentUpdateNewerTimeStamp,
    FastDeploy_AgentUpdateDifferentVersion
} FastDeploy_AgentUpdateStrategy;

static constexpr int kFastDeployMinApi = 24;

int get_device_api_level();
bool update_agent(FastDeploy_AgentUpdateStrategy agentUpdateStrategy, bool use_localagent,
                  const char* adb_path);
int extract_metadata(const char* apkPath, FILE* outputFp);
int create_patch(const char* apkPath, const char* metadataPath, const char* patchPath,
                 bool use_localagent, const char* adb_path);
int apply_patch_on_device(const char* apkPath, const char* patchPath, const char* outputPath);
int install_patch(const char* apkPath, const char* patchPath, int argc, const char** argv);
std::string get_patch_path(const char* apkPath);

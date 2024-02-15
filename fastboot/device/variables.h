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

#include <functional>
#include <string>
#include <vector>

class FastbootDevice;

bool GetVersion(FastbootDevice* device, const std::vector<std::string>& args, std::string* message);
bool GetBootloaderVersion(FastbootDevice* device, const std::vector<std::string>& args,
                          std::string* message);
bool GetBasebandVersion(FastbootDevice* device, const std::vector<std::string>& args,
                        std::string* message);
bool GetOsVersion(FastbootDevice* device, const std::vector<std::string>& args,
                  std::string* message);
bool GetVndkVersion(FastbootDevice* device, const std::vector<std::string>& args,
                    std::string* message);
bool GetProduct(FastbootDevice* device, const std::vector<std::string>& args, std::string* message);
bool GetSerial(FastbootDevice* device, const std::vector<std::string>& args, std::string* message);
bool GetSecure(FastbootDevice* device, const std::vector<std::string>& args, std::string* message);
bool GetCurrentSlot(FastbootDevice* device, const std::vector<std::string>& args,
                    std::string* message);
bool GetSlotCount(FastbootDevice* device, const std::vector<std::string>& args,
                  std::string* message);
bool GetSlotSuccessful(FastbootDevice* device, const std::vector<std::string>& args,
                       std::string* message);
bool GetSlotUnbootable(FastbootDevice* device, const std::vector<std::string>& args,
                       std::string* message);
bool GetMaxDownloadSize(FastbootDevice* device, const std::vector<std::string>& args,
                        std::string* message);
bool GetUnlocked(FastbootDevice* device, const std::vector<std::string>& args,
                 std::string* message);
bool GetHasSlot(FastbootDevice* device, const std::vector<std::string>& args, std::string* message);
bool GetPartitionSize(FastbootDevice* device, const std::vector<std::string>& args,
                      std::string* message);
bool GetPartitionType(FastbootDevice* device, const std::vector<std::string>& args,
                      std::string* message);
bool GetPartitionIsLogical(FastbootDevice* device, const std::vector<std::string>& args,
                           std::string* message);
bool GetIsUserspace(FastbootDevice* device, const std::vector<std::string>& args,
                    std::string* message);
bool GetIsForceDebuggable(FastbootDevice* device, const std::vector<std::string>& args,
                          std::string* message);
bool GetHardwareRevision(FastbootDevice* device, const std::vector<std::string>& args,
                         std::string* message);
bool GetVariant(FastbootDevice* device, const std::vector<std::string>& args, std::string* message);
bool GetOffModeChargeState(FastbootDevice* device, const std::vector<std::string>& args,
                           std::string* message);
bool GetBatteryVoltage(FastbootDevice* device, const std::vector<std::string>& args,
                       std::string* message);
bool GetBatterySoC(FastbootDevice* device, const std::vector<std::string>& args,
                   std::string* message);
bool GetBatterySoCOk(FastbootDevice* device, const std::vector<std::string>& args,
                     std::string* message);
bool GetBatterySerialNumber(FastbootDevice* device, const std::vector<std::string>& args,
                            std::string* message);
bool GetBatteryPartStatus(FastbootDevice* device, const std::vector<std::string>& args,
                          std::string* message);
bool GetSuperPartitionName(FastbootDevice* device, const std::vector<std::string>& args,
                           std::string* message);
bool GetSnapshotUpdateStatus(FastbootDevice* device, const std::vector<std::string>& args,
                             std::string* message);
bool GetCpuAbi(FastbootDevice* device, const std::vector<std::string>& args, std::string* message);
bool GetSystemFingerprint(FastbootDevice* device, const std::vector<std::string>& args,
                          std::string* message);
bool GetVendorFingerprint(FastbootDevice* device, const std::vector<std::string>& args,
                          std::string* message);
bool GetDynamicPartition(FastbootDevice* device, const std::vector<std::string>& args,
                         std::string* message);
bool GetFirstApiLevel(FastbootDevice* device, const std::vector<std::string>& args,
                      std::string* message);
bool GetSecurityPatchLevel(FastbootDevice* device, const std::vector<std::string>& args,
                           std::string* message);
bool GetTrebleEnabled(FastbootDevice* device, const std::vector<std::string>& args,
                      std::string* message);
bool GetMaxFetchSize(FastbootDevice* /* device */, const std::vector<std::string>& /* args */,
                     std::string* message);

// Complex cases.
bool GetDmesg(FastbootDevice* device);

// Helpers for getvar all.
std::vector<std::vector<std::string>> GetAllPartitionArgsWithSlot(FastbootDevice* device);
std::vector<std::vector<std::string>> GetAllPartitionArgsNoSlot(FastbootDevice* device);

/*
 * Copyright 2024, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <string>

#include <stddef.h>

std::string describe_tagged_addr_ctrl(long ctrl);
std::string describe_pac_enabled_keys(long keys);

// Number of bytes per MTE granule.
constexpr size_t kTagGranuleSize = 16;

// Number of rows and columns to display in an MTE tag dump.
constexpr size_t kNumTagColumns = 16;
constexpr size_t kNumTagRows = 16;

// Encode all non-ascii values and also ascii values that are not printable.
std::string oct_encode_non_ascii_printable(const std::string& data);
// Encode any value that fails isprint(), includes encoding chars like '\n' and '\t'.
std::string oct_encode_non_printable(const std::string& data);

/*
 * Copyright 2020 The Android Open Source Project
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

#include <stddef.h>

#include <log/log.h>

static constexpr size_t kDefaultLogBufferSize = 256 * 1024;
static constexpr size_t kLogBufferMinSize = 64 * 1024;
static constexpr size_t kLogBufferMaxSize = 256 * 1024 * 1024;

bool IsValidBufferSize(size_t value);

// This returns the buffer size as set in system properties for use in LogBuffer::Init().
// Note that `logcat -G` calls LogBuffer::SetSize(), which configures log buffer sizes without
// setting these properties, so this function should never be used except for LogBuffer::Init().
// LogBuffer::GetSize() should be used instead within logd.  Other processes can use
// android_logger_get_log_size() or `logcat -g` to query the actual allotted buffer size.
size_t GetBufferSizeFromProperties(log_id_t log_id);

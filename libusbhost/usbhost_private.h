/*
 * Copyright (C) 2022 The Android Open Source Project
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

#define LOG_TAG "usbhost"
#include <log/log.h>

// Somewhat arbitrary: Sony has reported needing more than 4KiB (but less
// than 8KiB), and some frameworks code had 16KiB without any explanation,
// so we went with the largest of those.
#define MAX_DESCRIPTORS_LENGTH (16 * 1024)

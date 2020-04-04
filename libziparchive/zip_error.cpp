/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "zip_error.h"

#include <android-base/macros.h>

static const char* kErrorMessages[] = {
    "Success",
    "Iteration ended",
    "Zlib error",
    "Invalid file",
    "Invalid handle",
    "Duplicate entries in archive",
    "Empty archive",
    "Entry not found",
    "Invalid offset",
    "Inconsistent information",
    "Invalid entry name",
    "I/O error",
    "File mapping failed",
    "Allocation failed",
    "Unsupported zip entry size",
};

const char* ErrorCodeString(int32_t error_code) {
  // Make sure that the number of entries in kErrorMessages and the ZipError
  // enum match.
  static_assert((-kLastErrorCode + 1) == arraysize(kErrorMessages),
                "(-kLastErrorCode + 1) != arraysize(kErrorMessages)");

  const uint32_t idx = -error_code;
  if (idx < arraysize(kErrorMessages)) {
    return kErrorMessages[idx];
  }

  return "Unknown return code";
}

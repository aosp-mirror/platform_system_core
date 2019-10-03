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

#include "adb_unique_fd.h"
#include "fastdeploy/proto/ApkEntry.pb.h"

/**
 * Helper class that mirrors the PatchUtils from deploy agent.
 */
class PatchUtils {
  public:
    /**
     * This function takes the dump of Central Directly and builds the APKMetaData required by the
     * patching algorithm. The if this function has an error a string is printed to the terminal and
     * exit(1) is called.
     */
    static com::android::fastdeploy::APKMetaData GetDeviceAPKMetaData(
            const com::android::fastdeploy::APKDump& apk_dump);
    /**
     * This function takes a local APK file and builds the APKMetaData required by the patching
     * algorithm. The if this function has an error a string is printed to the terminal and exit(1)
     * is called.
     */
    static com::android::fastdeploy::APKMetaData GetHostAPKMetaData(const char* file);
    /**
     * Writes a fixed signature string to the header of the patch.
     */
    static void WriteSignature(android::base::borrowed_fd output);
    /**
     * Writes an int64 to the |output| reversing the bytes.
     */
    static void WriteLong(int64_t value, android::base::borrowed_fd output);
    /**
     * Writes string to the |output|.
     */
    static void WriteString(const std::string& value, android::base::borrowed_fd output);
    /**
     * Copy |amount| of data from |input| to |output|.
     */
    static void Pipe(android::base::borrowed_fd input, android::base::borrowed_fd output,
                     size_t amount);
};

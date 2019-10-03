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

#include <vector>

#include "adb_unique_fd.h"
#include "fastdeploy/proto/ApkEntry.pb.h"

/**
 * This class is responsible for creating a patch that can be accepted by the deployagent. The
 * patch format is documented in GeneratePatch.
 */
class DeployPatchGenerator {
  public:
    using APKEntry = com::android::fastdeploy::APKEntry;
    using APKMetaData = com::android::fastdeploy::APKMetaData;

    /**
     * Simple struct to hold mapping between local metadata and device metadata.
     */
    struct SimpleEntry {
        const APKEntry* localEntry;
        const APKEntry* deviceEntry;
    };

    /**
     * If |is_verbose| is true ApkEntries that are similar between device and host are written to
     * the console.
     */
    explicit DeployPatchGenerator(bool is_verbose) : is_verbose_(is_verbose) {}
    /**
     * Given a |localApkPath|, and the |deviceApkMetadata| from an installed APK this function
     * writes a patch to the given |output|.
     */
    bool CreatePatch(const char* localApkPath, APKMetaData deviceApkMetadata,
                     android::base::borrowed_fd output);

  private:
    bool is_verbose_;

    /**
     * Log function only logs data to stdout when |is_verbose_| is true.
     */
    void Log(const char* fmt, ...) __attribute__((__format__(__printf__, 2, 3)));

    /**
     * Helper function to log the APKMetaData structure. If |is_verbose_| is false this function
     * early outs. This function is used for debugging / information.
     */
    void APKMetaDataToLog(const APKMetaData& metadata);
    /**
     * Helper function to log APKEntry.
     */
    void APKEntryToLog(const APKEntry& entry);

    /**
     * Given the |localApkMetadata| metadata, and the |deviceApkMetadata| from an installed APK this
     * function writes a patch to the given |output|.
     */
    bool CreatePatch(APKMetaData localApkMetadata, APKMetaData deviceApkMetadata,
                     android::base::borrowed_fd output);

    /**
     * Helper function to report savings by fastdeploy. This function prints out savings even with
     * |is_verbose_| set to false. |totalSize| is used to show a percentage of savings. Note:
     * |totalSize| is the size of the ZipEntries. Not the size of the entire file. The metadata of
     * the zip data needs to be sent across with every iteration.
     * [Patch format]
     * |Fixed String| Signature
     * |long|         New Size of Apk
     * |Packets[]|    Array of Packets
     *
     * [Packet Format]
     * |long|     Size of data to use from patch
     * |byte[]|   Patch data
     * |long|     Offset of data to use already on device
     * |long|     Length of data to read from device APK
     * TODO(b/138306784): Move the patch format to a proto.
     */
    void ReportSavings(const std::vector<SimpleEntry>& identicalEntries, uint64_t totalSize);

    /**
     * This enumerates each entry in |entriesToUseOnDevice| and builds a patch file copying data
     * from |localApkPath| where we are unable to use entries already on the device. The new patch
     * is written to |output|. The entries are expected to be sorted by data offset from lowest to
     * highest.
     */
    void GeneratePatch(const std::vector<SimpleEntry>& entriesToUseOnDevice,
                       const std::string& localApkPath, const std::string& deviceApkPath,
                       android::base::borrowed_fd output);

  protected:
    uint64_t BuildIdenticalEntries(std::vector<SimpleEntry>& outIdenticalEntries,
                                   const APKMetaData& localApkMetadata,
                                   const APKMetaData& deviceApkMetadata);
};

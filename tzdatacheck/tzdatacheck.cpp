/*
 * Copyright (C) 2015 The Android Open Source Project
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

#include <errno.h>
#include <ftw.h>
#include <libgen.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "base/logging.h"

static const char* TZDATA_FILENAME = "/tzdata";
// tzdata file header (as much as we need for the version):
// byte[11] tzdata_version  -- e.g. "tzdata2012f"
static const int TZ_HEADER_LENGTH = 11;

static void usage() {
    std::cerr << "Usage: tzdatacheck SYSTEM_TZ_DIR DATA_TZ_DIR\n"
            "\n"
            "Compares the headers of two tzdata files. If the one in SYSTEM_TZ_DIR is the\n"
            "same or a higher version than the one in DATA_TZ_DIR the DATA_TZ_DIR is renamed\n"
            "and then deleted.\n";
    exit(1);
}

/*
 * Opens a file and fills headerBytes with the first byteCount bytes from the file. It is a fatal
 * error if the file is too small or cannot be opened. If the file does not exist false is returned.
 * If the bytes were read successfully then true is returned.
 */
static bool readHeader(const std::string& tzDataFileName, char* headerBytes, size_t byteCount) {
    FILE* tzDataFile = fopen(tzDataFileName.c_str(), "r");
    if (tzDataFile == nullptr) {
        if (errno == ENOENT) {
            return false;
        } else {
            PLOG(FATAL) << "Error opening tzdata file " << tzDataFileName;
        }
    }
    size_t bytesRead = fread(headerBytes, 1, byteCount, tzDataFile);
    if (bytesRead != byteCount) {
        LOG(FATAL) << tzDataFileName << " is too small. " << byteCount << " bytes required";
    }
    fclose(tzDataFile);
    return true;
}

/* Checks the contents of headerBytes. It is a fatal error if it not a tzdata header. */
static void checkValidHeader(const std::string& fileName, char* headerBytes) {
    if (strncmp("tzdata", headerBytes, 6) != 0) {
        LOG(FATAL) << fileName << " does not start with the expected bytes (tzdata)";
    }
}

/* Return the parent directory of dirName. */
static std::string getParentDir(const std::string& dirName) {
    std::unique_ptr<char> mutable_dirname(strdup(dirName.c_str()));
    return dirname(mutable_dirname.get());
}

/* Deletes a single file, symlink or directory. Called from nftw(). */
static int deleteFn(const char* fpath, const struct stat*, int typeflag, struct FTW*) {
    LOG(DEBUG) << "Inspecting " << fpath;
    switch (typeflag) {
    case FTW_F:
    case FTW_SL:
        LOG(DEBUG) << "Unlinking " << fpath;
        if (unlink(fpath)) {
            PLOG(WARNING) << "Failed to unlink file/symlink " << fpath;
        }
        break;
    case FTW_D:
    case FTW_DP:
        LOG(DEBUG) << "Removing dir " << fpath;
        if (rmdir(fpath)) {
            PLOG(WARNING) << "Failed to remove dir " << fpath;
        }
        break;
    default:
        LOG(WARNING) << "Unsupported file type " << fpath << ": " << typeflag;
        break;
    }
    return 0;
}

/*
 * Deletes dirToDelete and returns true if it is successful in removing or moving the directory out
 * of the way. If dirToDelete does not exist this function does nothing and returns true.
 *
 * During deletion, this function first renames the directory to a temporary name. If the temporary
 * directory cannot be created, or the directory cannot be renamed, false is returned. After the
 * rename, deletion of files and subdirs beneath the directory is performed on a "best effort"
 * basis. Symlinks beneath the directory are not followed.
 */
static bool deleteDir(const std::string& dirToDelete) {
    // Check whether the dir exists.
    struct stat buf;
    if (stat(dirToDelete.c_str(), &buf) == 0) {
      if (!S_ISDIR(buf.st_mode)) {
        LOG(WARNING) << dirToDelete << " is not a directory";
        return false;
      }
    } else {
      if (errno == ENOENT) {
          PLOG(INFO) << "Directory does not exist: " << dirToDelete;
          return true;
      } else {
          PLOG(WARNING) << "Unable to stat " << dirToDelete;
          return false;
      }
    }

    // First, rename dirToDelete.
    std::string tempDirNameTemplate = getParentDir(dirToDelete);
    tempDirNameTemplate += "/tempXXXXXX";

    // Create an empty directory with the temporary name. For this we need a non-const char*.
    std::vector<char> tempDirName(tempDirNameTemplate.length() + 1);
    strcpy(&tempDirName[0], tempDirNameTemplate.c_str());
    if (mkdtemp(&tempDirName[0]) == nullptr) {
        PLOG(WARNING) << "Unable to create a temporary directory: " << tempDirNameTemplate;
        return false;
    }

    // Rename dirToDelete to tempDirName.
    int rc = rename(dirToDelete.c_str(), &tempDirName[0]);
    if (rc == -1) {
        PLOG(WARNING) << "Unable to rename directory from " << dirToDelete << " to "
                << &tempDirName[0];
        return false;
    }

    // Recursively delete contents of tempDirName.
    rc = nftw(&tempDirName[0], deleteFn, 10 /* openFiles */,
            FTW_DEPTH | FTW_MOUNT | FTW_PHYS);
    if (rc == -1) {
        LOG(INFO) << "Could not delete directory: " << &tempDirName[0];
    }
    return true;
}

/*
 * After a platform update it is likely that timezone data found on the system partition will be
 * newer than the version found in the data partition. This tool detects this case and removes the
 * version in /data along with any update metadata.
 *
 * Note: This code is related to code in com.android.server.updates.TzDataInstallReceiver. The
 * paths for the metadata and current timezone data must match.
 *
 * Typically on device the two args will be:
 *   /system/usr/share/zoneinfo /data/misc/zoneinfo
 *
 * See usage() for usage notes.
 */
int main(int argc, char* argv[]) {
    if (argc != 3) {
        usage();
    }

    const char* systemZoneInfoDir = argv[1];
    const char* dataZoneInfoDir = argv[2];

    std::string dataCurrentDirName(dataZoneInfoDir);
    dataCurrentDirName += "/current";
    std::string dataTzDataFileName(dataCurrentDirName);
    dataTzDataFileName += TZDATA_FILENAME;

    std::vector<char> dataTzDataHeader;
    dataTzDataHeader.reserve(TZ_HEADER_LENGTH);

    bool dataFileExists = readHeader(dataTzDataFileName, dataTzDataHeader.data(), TZ_HEADER_LENGTH);
    if (!dataFileExists) {
        LOG(INFO) << "tzdata file " << dataTzDataFileName << " does not exist. No action required.";
        return 0;
    }
    checkValidHeader(dataTzDataFileName, dataTzDataHeader.data());

    std::string systemTzDataFileName(systemZoneInfoDir);
    systemTzDataFileName += TZDATA_FILENAME;
    std::vector<char> systemTzDataHeader;
    systemTzDataHeader.reserve(TZ_HEADER_LENGTH);
    bool systemFileExists =
            readHeader(systemTzDataFileName, systemTzDataHeader.data(), TZ_HEADER_LENGTH);
    if (!systemFileExists) {
        LOG(FATAL) << systemTzDataFileName << " does not exist or could not be opened";
    }
    checkValidHeader(systemTzDataFileName, systemTzDataHeader.data());

    if (strncmp(&systemTzDataHeader[0], &dataTzDataHeader[0], TZ_HEADER_LENGTH) < 0) {
        LOG(INFO) << "tzdata file " << dataTzDataFileName << " is the newer than "
                << systemTzDataFileName << ". No action required.";
    } else {
        // We have detected the case this tool is intended to prevent. Go fix it.
        LOG(INFO) << "tzdata file " << dataTzDataFileName << " is the same as or older than "
                << systemTzDataFileName << "; fixing...";

        // Delete the update metadata
        std::string dataUpdatesDirName(dataZoneInfoDir);
        dataUpdatesDirName += "/updates";
        LOG(INFO) << "Removing: " << dataUpdatesDirName;
        bool deleted = deleteDir(dataUpdatesDirName);
        if (!deleted) {
            LOG(WARNING) << "Deletion of install metadata " << dataUpdatesDirName
                    << " was not successful";
        }

        // Delete the TZ data
        LOG(INFO) << "Removing: " << dataCurrentDirName;
        deleted = deleteDir(dataCurrentDirName);
        if (!deleted) {
            LOG(WARNING) << "Deletion of tzdata " << dataCurrentDirName << " was not successful";
        }
    }

    return 0;
}

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

#include <ctype.h>
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

#include "android-base/logging.h"

// The name of the directory that holds a staged time zone update distro. If this exists it should
// replace the one in CURRENT_DIR_NAME.
// See also libcore.tzdata.update2.TimeZoneDistroInstaller.
static const char* STAGED_DIR_NAME = "/staged";

// The name of the directory that holds the (optional) installed time zone update distro.
// See also libcore.tzdata.update2.TimeZoneDistroInstaller.
static const char* CURRENT_DIR_NAME = "/current";

// The name of a file in the staged dir that indicates the staged operation is an "uninstall".
// See also libcore.tzdata.update2.TimeZoneDistroInstaller.
static const char* UNINSTALL_TOMBSTONE_FILE_NAME = "/STAGED_UNINSTALL_TOMBSTONE";

// The name of the file containing the distro version information.
// See also libcore.tzdata.shared2.TimeZoneDistro / libcore.tzdata.shared2.DistroVersion.
static const char* DISTRO_VERSION_FILENAME = "/distro_version";

// distro_version is an ASCII file consisting of 17 bytes in the form: AAA.BBB|CCCCC|DDD
// AAA.BBB is the major/minor version of the distro format (e.g. 001.001),
// CCCCC is the rules version (e.g. 2016g)
// DDD is the android revision for this rules version to allow for distro corrections (e.g. 001)
// We only need the first 13 to determine if it is suitable for the device.
static const int DISTRO_VERSION_LENGTH = 13;

// The major version of the distro format supported by this code as a null-terminated char[].
// See also libcore.tzdata.shared2.TimeZoneDistro / libcore.tzdata.shared2.DistroVersion.
static const char SUPPORTED_DISTRO_MAJOR_VERSION[] = "001";

// The length of the distro format major version excluding the \0
static const size_t SUPPORTED_DISTRO_MAJOR_VERSION_LEN = sizeof(SUPPORTED_DISTRO_MAJOR_VERSION) - 1;

// The minor version of the distro format supported by this code as a null-terminated char[].
// See also libcore.tzdata.shared2.TimeZoneDistro / libcore.tzdata.shared2.DistroVersion.
static const char SUPPORTED_DISTRO_MINOR_VERSION[] = "001";

// The length of the distro format minor version excluding the \0
static const size_t SUPPORTED_DISTRO_MINOR_VERSION_LEN = sizeof(SUPPORTED_DISTRO_MINOR_VERSION) - 1;

// The length of the distro format version. e.g. 001.001
static const size_t SUPPORTED_DISTRO_VERSION_LEN =
        SUPPORTED_DISTRO_MAJOR_VERSION_LEN + SUPPORTED_DISTRO_MINOR_VERSION_LEN + 1;

// The length of the IANA rules version bytes. e.g. 2016a
static const size_t RULES_VERSION_LEN = 5;

// Distro version bytes are: AAA.BBB|CCCCC - the rules version is CCCCC
static const size_t DISTRO_VERSION_RULES_IDX = 8;

// See also libcore.tzdata.shared2.TimeZoneDistro.
static const char* TZDATA_FILENAME = "/tzdata";

// tzdata file header (as much as we need for the version):
// byte[11] tzdata_version  -- e.g. "tzdata2012f"
static const int TZ_HEADER_LENGTH = 11;

static const char TZ_DATA_HEADER_PREFIX[] = "tzdata";
static const size_t TZ_DATA_HEADER_PREFIX_LEN = sizeof(TZ_DATA_HEADER_PREFIX) - 1; // exclude \0

static void usage() {
    std::cerr << "Usage: tzdatacheck SYSTEM_TZ_DIR DATA_TZ_DIR\n"
            "\n"
            "Checks whether any timezone update distro in DATA_TZ_DIR is compatible with the\n"
            "current Android release and better than or the same as base system timezone rules in\n"
            "SYSTEM_TZ_DIR. If the timezone rules in SYSTEM_TZ_DIR are a higher version than the\n"
            "one in DATA_TZ_DIR the DATA_TZ_DIR is renamed and then deleted.\n";
    exit(1);
}

/*
 * Opens a file and fills buffer with the first byteCount bytes from the file.
 * If the file does not exist or cannot be opened or is too short then false is returned.
 * If the bytes were read successfully then true is returned.
 */
static bool readBytes(const std::string& fileName, char* buffer, size_t byteCount) {
    FILE* file = fopen(fileName.c_str(), "r");
    if (file == nullptr) {
        if (errno != ENOENT) {
            PLOG(WARNING) << "Error opening file " << fileName;
        }
        return false;
    }
    size_t bytesRead = fread(buffer, 1, byteCount, file);
    fclose(file);
    if (bytesRead != byteCount) {
        LOG(WARNING) << fileName << " is too small. " << byteCount << " bytes required";
        return false;
    }
    return true;
}

/*
 * Checks the contents of headerBytes. Returns true if it is valid (starts with "tzdata"), false
 * otherwise.
 */
static bool checkValidTzDataHeader(const std::string& fileName, const char* headerBytes) {
    if (strncmp("tzdata", headerBytes, 6) != 0) {
        LOG(WARNING) << fileName << " does not start with the expected bytes (tzdata)";
        return false;
    }
    return true;
}

static bool checkDigits(const char* buffer, const size_t count, size_t* i) {
    for (size_t j = 0; j < count; j++) {
      char toCheck = buffer[(*i)++];
      if (!isdigit(toCheck)) {
        return false;
      }
    }
    return true;
}

static bool checkValidDistroVersion(const char* buffer) {
    // See DISTRO_VERSION_LENGTH comments above for a description of the format.
    size_t i = 0;
    if (!checkDigits(buffer, 3, &i)) {
      return false;
    }
    if (buffer[i++] != '.') {
      return false;
    }
    if (!checkDigits(buffer, 3, &i)) {
      return false;
    }
    if (buffer[i++] != '|') {
      return false;
    }
    if (!checkDigits(buffer, 4, &i)) {
      return false;
    }
    // Ignore the last character. It is assumed to be a letter but we don't check because it's not
    // obvious what would happen at 'z'.
    return true;
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

enum PathStatus { ERR, NONE, IS_DIR, IS_REG, UNKNOWN };

static PathStatus checkPath(const std::string& path) {
    struct stat buf;
    if (stat(path.c_str(), &buf) != 0) {
        if (errno != ENOENT) {
            PLOG(WARNING) << "Unable to stat " << path;
            return ERR;
        }
        return NONE;
    }
    return S_ISDIR(buf.st_mode) ? IS_DIR : S_ISREG(buf.st_mode) ? IS_REG : UNKNOWN;
}

/*
 * Deletes fileToDelete and returns true if it is successful. If fileToDelete is not a file or
 * cannot be accessed this method returns false.
 */
static bool deleteFile(const std::string& fileToDelete) {
    // Check whether the file exists.
    PathStatus pathStatus = checkPath(fileToDelete);
    if (pathStatus == NONE) {
        LOG(INFO) << "Path " << fileToDelete << " does not exist";
        return true;
    }
    if (pathStatus != IS_REG) {
        LOG(WARNING) << "Path " << fileToDelete << " failed to stat() or is not a file.";
        return false;
    }

    // Attempt the deletion.
    int rc = unlink(fileToDelete.c_str());
    if (rc != 0) {
        PLOG(WARNING) << "unlink() failed for " << fileToDelete;
    }
    return rc == 0;
}

/*
 * Deletes dirToDelete and returns true if it is successful in removing or moving the directory out
 * of the way. If dirToDelete does not exist this function does nothing and returns true. If
 * dirToDelete is not a directory or cannot be accessed this method returns false.
 *
 * During deletion, this function first renames the directory to a temporary name. If the temporary
 * directory cannot be created, or the directory cannot be renamed, false is returned. After the
 * rename, deletion of files and subdirs beneath the directory is performed on a "best effort"
 * basis. Symlinks beneath the directory are not followed.
 */
static bool deleteDir(const std::string& dirToDelete) {
    // Check whether the dir exists.
    int pathStatus = checkPath(dirToDelete);
    if (pathStatus == NONE) {
        LOG(INFO) << "Path " << dirToDelete << " does not exist";
        return true;
    }
    if (pathStatus != IS_DIR) {
        LOG(WARNING) << "Path " << dirToDelete << " failed to stat() or is not a directory.";
        return false;
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

    // Rename dirToDelete to tempDirName (replacing the empty tempDirName directory created above).
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
 * Deletes the ConfigInstaller metadata directory.
 * TODO(nfuller). http://b/31008728 Remove this when ConfigInstaller is no longer used.
 */
static void deleteConfigUpdaterMetadataDir(const char* dataZoneInfoDir) {
    // Delete the update metadata
    std::string dataUpdatesDirName(dataZoneInfoDir);
    dataUpdatesDirName += "/updates";
    LOG(INFO) << "Removing: " << dataUpdatesDirName;
    if (!deleteDir(dataUpdatesDirName)) {
        LOG(WARNING) << "Deletion of install metadata " << dataUpdatesDirName
                << " was not successful";
    }
}

/*
 * Deletes the timezone update distro directory.
 */
static void deleteUpdateDistroDir(const std::string& distroDirName) {
    LOG(INFO) << "Removing: " << distroDirName;
    if (!deleteDir(distroDirName)) {
        LOG(WARNING) << "Deletion of distro dir " << distroDirName << " was not successful";
    }
}

static void handleStagedUninstall(const std::string& dataStagedDirName,
                                  const std::string& dataCurrentDirName,
                                  const PathStatus dataCurrentDirStatus) {
    LOG(INFO) << "Staged operation is an uninstall.";

    // Delete the current install directory.
    switch (dataCurrentDirStatus) {
        case NONE:
            // This is unexpected: No uninstall should be staged if there is nothing to
            // uninstall. Carry on anyway.
            LOG(WARNING) << "No current install to delete.";
            break;
        case IS_DIR:
            // This is normal. Delete the current install dir.
            if (!deleteDir(dataCurrentDirName)) {
                LOG(WARNING) << "Deletion of current distro " << dataCurrentDirName
                             << " was not successful";
                // If this happens we don't know whether we were able to delete or not. We don't
                // delete the staged operation so it will be retried next boot unless overridden.
                return;
            }
            break;
        case IS_REG:
        default:
            // This is unexpected: We can try to delete the unexpected file and carry on.
            LOG(WARNING) << "Current distro dir " << dataCurrentDirName
                         << " is not actually a directory. Attempting deletion.";
            if (!deleteFile(dataCurrentDirName)) {
                LOG(WARNING) << "Could not delete " << dataCurrentDirName;
                return;
            }
            break;
    }

    // Delete the staged uninstall dir.
    if (!deleteDir(dataStagedDirName)) {
        LOG(WARNING) << "Deletion of current distro " << dataCurrentDirName
                     << " was not successful";
        // If this happens we don't know whether we were able to delete the staged operation
        // or not.
        return;
    }
    LOG(INFO) << "Staged uninstall complete.";
}

static void handleStagedInstall(const std::string& dataStagedDirName,
                                const std::string& dataCurrentDirName,
                                const PathStatus dataCurrentDirStatus) {
    LOG(INFO) << "Staged operation is an install.";

    switch (dataCurrentDirStatus) {
        case NONE:
            // This is expected: This is the first install.
            LOG(INFO) << "No current install to replace.";
            break;
        case IS_DIR:
            // This is expected: We are replacing an existing install.
            // Delete the current dir so we can replace it.
            if (!deleteDir(dataCurrentDirName)) {
                LOG(WARNING) << "Deletion of current distro " << dataCurrentDirName
                             << " was not successful";
                // If this happens, we cannot proceed.
                return;
            }
            break;
        case IS_REG:
        default:
            // This is unexpected: We can try to delete the unexpected file and carry on.
            LOG(WARNING) << "Current distro dir " << dataCurrentDirName
                         << " is not actually a directory. Attempting deletion.";
            if (!deleteFile(dataCurrentDirName)) {
                LOG(WARNING) << "Could not delete " << dataCurrentDirName;
                return;
            }
            break;
    }

    // Move the staged dir so it is the new current dir, completing the install.
    LOG(INFO) << "Moving " << dataStagedDirName << " to " << dataCurrentDirName;
    int rc = rename(dataStagedDirName.c_str(), dataCurrentDirName.c_str());
    if (rc == -1) {
        PLOG(WARNING) << "Unable to rename directory from " << dataStagedDirName << " to "
                      << &dataCurrentDirName[0];
        return;
    }

    LOG(INFO) << "Staged install complete.";
}
/*
 * Process a staged operation if there is one.
 */
static void processStagedOperation(const std::string& dataStagedDirName,
                                   const std::string& dataCurrentDirName) {
    PathStatus dataStagedDirStatus = checkPath(dataStagedDirName);

    // Exit early for the common case.
    if (dataStagedDirStatus == NONE) {
        LOG(DEBUG) << "No staged time zone operation.";
        return;
    }

    // Check known directory names are in a good starting state.
    if (dataStagedDirStatus != IS_DIR) {
        LOG(WARNING) << "Staged distro dir " << dataStagedDirName
                     << " could not be accessed or is not a directory."
                     << " stagedDirStatus=" << dataStagedDirStatus;
        return;
    }

    // dataStagedDirStatus == IS_DIR.

    // Work out whether there is anything currently installed.
    PathStatus dataCurrentDirStatus = checkPath(dataCurrentDirName);
    if (dataCurrentDirStatus == ERR) {
        LOG(WARNING) << "Current install dir " << dataCurrentDirName << " could not be accessed"
                     << " dataCurrentDirStatus=" << dataCurrentDirStatus;
        return;
    }

    // We must perform the staged operation.

    // Check to see if the staged directory contains an uninstall or an install operation.
    std::string uninstallTombStoneFile(dataStagedDirName);
    uninstallTombStoneFile += UNINSTALL_TOMBSTONE_FILE_NAME;
    int uninstallTombStoneFileStatus = checkPath(uninstallTombStoneFile);
    if (uninstallTombStoneFileStatus != IS_REG && uninstallTombStoneFileStatus != NONE) {
        // Error case.
        LOG(WARNING) << "Unable to determine if the staged operation is an uninstall.";
        return;
    }
    if (uninstallTombStoneFileStatus == IS_REG) {
        handleStagedUninstall(dataStagedDirName, dataCurrentDirName, dataCurrentDirStatus);
    } else {
        // uninstallTombStoneFileStatus == NONE meaning this is a staged install.
        handleStagedInstall(dataStagedDirName, dataCurrentDirName, dataCurrentDirStatus);
    }
}

/*
 * After a platform update it is likely that timezone data found on the system partition will be
 * newer than the version found in the data partition. This tool detects this case and removes the
 * version in /data.
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
        return 1;
    }

    const char* systemZoneInfoDir = argv[1];
    const char* dataZoneInfoDir = argv[2];

    std::string dataStagedDirName(dataZoneInfoDir);
    dataStagedDirName += STAGED_DIR_NAME;

    std::string dataCurrentDirName(dataZoneInfoDir);
    dataCurrentDirName += CURRENT_DIR_NAME;

    // Check for an process any staged operation.
    // If the staged operation could not be handled we still have to validate the current installed
    // directory so we do not check for errors and do not quit early.
    processStagedOperation(dataStagedDirName, dataCurrentDirName);

    // Check the distro directory exists. If it does not, exit quickly: nothing to do.
    PathStatus dataCurrentDirStatus = checkPath(dataCurrentDirName);
    if (dataCurrentDirStatus == NONE) {
        LOG(INFO) << "timezone distro dir " << dataCurrentDirName
                << " does not exist. No action required.";
        return 0;
    }

    // If the distro directory path is not a directory or we can't stat() the path, exit with a
    // warning: either there's a problem accessing storage or the world is not as it should be;
    // nothing to do.
    if (dataCurrentDirStatus != IS_DIR) {
        LOG(WARNING) << "Current distro dir " << dataCurrentDirName
                << " could not be accessed or is not a directory. result=" << dataCurrentDirStatus;
        return 2;
    }

    // Check the installed distro version.
    std::string distroVersionFileName(dataCurrentDirName);
    distroVersionFileName += DISTRO_VERSION_FILENAME;
    std::vector<char> distroVersion;
    distroVersion.reserve(DISTRO_VERSION_LENGTH);
    bool distroVersionReadOk =
            readBytes(distroVersionFileName, distroVersion.data(), DISTRO_VERSION_LENGTH);
    if (!distroVersionReadOk) {
        LOG(WARNING) << "distro version file " << distroVersionFileName
                << " does not exist or is too short. Deleting distro dir.";
        // Implies the contents of the data partition is corrupt in some way. Try to clean up.
        deleteConfigUpdaterMetadataDir(dataZoneInfoDir);
        deleteUpdateDistroDir(dataCurrentDirName);
        return 3;
    }

    if (!checkValidDistroVersion(distroVersion.data())) {
        LOG(WARNING) << "distro version file " << distroVersionFileName
                << " is not valid. Deleting distro dir.";
        // Implies the contents of the data partition is corrupt in some way. Try to clean up.
        deleteConfigUpdaterMetadataDir(dataZoneInfoDir);
        deleteUpdateDistroDir(dataCurrentDirName);
        return 4;
    }

    std::string actualDistroVersion =
            std::string(distroVersion.data(), SUPPORTED_DISTRO_VERSION_LEN);
    // Check the first 3 bytes of the distro version: these are the major version (e.g. 001).
    // It must match the one we support exactly to be ok.
    if (strncmp(
            &distroVersion[0],
            SUPPORTED_DISTRO_MAJOR_VERSION,
            SUPPORTED_DISTRO_MAJOR_VERSION_LEN) != 0) {

        LOG(INFO) << "distro version file " << distroVersionFileName
                << " major version is not the required version " << SUPPORTED_DISTRO_MAJOR_VERSION
                << ", was \"" << actualDistroVersion << "\". Deleting distro dir.";
        // This implies there has been an OTA and the installed distro is not compatible with the
        // new version of Android. Remove the installed distro.
        deleteConfigUpdaterMetadataDir(dataZoneInfoDir);
        deleteUpdateDistroDir(dataCurrentDirName);
        return 5;
    }

    // Check the last 3 bytes of the distro version: these are the minor version (e.g. 001).
    // If the version in the distro is < the minor version required by this device it cannot be
    // used.
    if (strncmp(
            &distroVersion[4],
            SUPPORTED_DISTRO_MINOR_VERSION,
            SUPPORTED_DISTRO_MINOR_VERSION_LEN) < 0) {

        LOG(INFO) << "distro version file " << distroVersionFileName
                << " minor version is not the required version " << SUPPORTED_DISTRO_MINOR_VERSION
                << ", was \"" << actualDistroVersion << "\". Deleting distro dir.";
        // This implies there has been an OTA and the installed distro is not compatible with the
        // new version of Android. Remove the installed distro.
        deleteConfigUpdaterMetadataDir(dataZoneInfoDir);
        deleteUpdateDistroDir(dataCurrentDirName);
        return 5;
    }

    // Read the system rules version out of the /system tzdata file.
    std::string systemTzDataFileName(systemZoneInfoDir);
    systemTzDataFileName += TZDATA_FILENAME;
    std::vector<char> systemTzDataHeader;
    systemTzDataHeader.reserve(TZ_HEADER_LENGTH);
    bool systemFileExists =
            readBytes(systemTzDataFileName, systemTzDataHeader.data(), TZ_HEADER_LENGTH);
    if (!systemFileExists) {
        // Implies the contents of the system partition is corrupt in some way. Nothing we can do.
        LOG(WARNING) << systemTzDataFileName << " does not exist or could not be opened";
        return 6;
    }
    if (!checkValidTzDataHeader(systemTzDataFileName, systemTzDataHeader.data())) {
        // Implies the contents of the system partition is corrupt in some way. Nothing we can do.
        LOG(WARNING) << systemTzDataFileName << " does not have a valid header.";
        return 7;
    }

    // Compare the distro rules version against the system rules version.
    if (strncmp(
            &systemTzDataHeader[TZ_DATA_HEADER_PREFIX_LEN],
            &distroVersion[DISTRO_VERSION_RULES_IDX],
            RULES_VERSION_LEN) <= 0) {
        LOG(INFO) << "Found an installed distro but it is valid. No action taken.";
        // Implies there is an installed update, but it is good.
        return 0;
    }

    // Implies there has been an OTA and the system version of the timezone rules is now newer
    // than the version installed in /data. Remove the installed distro.
    LOG(INFO) << "timezone distro in " << dataCurrentDirName << " is older than data in "
            << systemTzDataFileName << "; fixing...";

    deleteConfigUpdaterMetadataDir(dataZoneInfoDir);
    deleteUpdateDistroDir(dataCurrentDirName);
    return 0;
}

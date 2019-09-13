/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include "fscrypt_init_extensions.h"

#include <dirent.h>
#include <errno.h>
#include <fts.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#include <string>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <cutils/properties.h>
#include <cutils/sockets.h>
#include <fscrypt/fscrypt.h>
#include <keyutils.h>
#include <logwrap/logwrap.h>

#define TAG "fscrypt"

static int set_policy_on(const std::string& ref_basename, const std::string& dir);

int fscrypt_install_keyring() {
    key_serial_t device_keyring = add_key("keyring", "fscrypt", 0, 0, KEY_SPEC_SESSION_KEYRING);

    if (device_keyring == -1) {
        PLOG(ERROR) << "Failed to create keyring";
        return -1;
    }

    LOG(INFO) << "Keyring created with id " << device_keyring << " in process " << getpid();

    return 0;
}

// TODO(b/139378601): use a single central implementation of this.
static void delete_dir_contents(const std::string& dir) {
    char* const paths[2] = {const_cast<char*>(dir.c_str()), nullptr};
    FTS* fts = fts_open(paths, FTS_PHYSICAL | FTS_NOCHDIR | FTS_XDEV, nullptr);
    FTSENT* cur;
    while ((cur = fts_read(fts)) != nullptr) {
        if (cur->fts_info == FTS_ERR) {
            PLOG(ERROR) << "fts_read";
            break;
        }
        if (dir == cur->fts_path) {
            continue;
        }
        switch (cur->fts_info) {
            case FTS_D:
                break;  // Ignore these
            case FTS_DP:
                if (rmdir(cur->fts_path) == -1) {
                    PLOG(ERROR) << "rmdir " << cur->fts_path;
                }
                break;
            default:
                PLOG(ERROR) << "FTS unexpected type " << cur->fts_info << " at " << cur->fts_path;
                if (rmdir(cur->fts_path) != -1) break;
                // FALLTHRU (for gcc, lint, pcc, etc; and following for clang)
                FALLTHROUGH_INTENDED;
            case FTS_F:
            case FTS_SL:
            case FTS_SLNONE:
                if (unlink(cur->fts_path) == -1) {
                    PLOG(ERROR) << "unlink " << cur->fts_path;
                }
                break;
        }
    }

    if (fts_close(fts) != 0) {
        PLOG(ERROR) << "fts_close";
    }
}

int fscrypt_set_directory_policy(const std::string& dir) {
    const std::string prefix = "/data/";

    if (!android::base::StartsWith(dir, prefix)) {
        return 0;
    }

    // Special-case /data/media/obb per b/64566063
    if (dir == "/data/media/obb") {
        // Try to set policy on this directory, but if it is non-empty this may fail.
        set_policy_on(fscrypt_key_ref, dir);
        return 0;
    }

    // Only set policy on first level /data directories
    // To make this less restrictive, consider using a policy file.
    // However this is overkill for as long as the policy is simply
    // to apply a global policy to all /data folders created via makedir
    if (dir.find_first_of('/', prefix.size()) != std::string::npos) {
        return 0;
    }

    // Special case various directories that must not be encrypted,
    // often because their subdirectories must be encrypted.
    // This isn't a nice way to do this, see b/26641735
    std::vector<std::string> directories_to_exclude = {
        "lost+found",
        "system_ce", "system_de",
        "misc_ce", "misc_de",
        "vendor_ce", "vendor_de",
        "media",
        "data", "user", "user_de",
        "apex", "preloads", "app-staging",
        "gsi",
    };
    for (const auto& d : directories_to_exclude) {
        if ((prefix + d) == dir) {
            LOG(INFO) << "Not setting policy on " << dir;
            return 0;
        }
    }
    std::vector<std::string> per_boot_directories = {
            "per_boot",
    };
    for (const auto& d : per_boot_directories) {
        if ((prefix + d) == dir) {
            LOG(INFO) << "Setting per_boot key on " << dir;
            return set_policy_on(fscrypt_key_per_boot_ref, dir);
        }
    }
    int err = set_policy_on(fscrypt_key_ref, dir);
    if (err == 0) {
        return 0;
    }
    // Empty these directories if policy setting fails.
    std::vector<std::string> wipe_on_failure = {
            "rollback", "rollback-observer",  // b/139193659
    };
    for (const auto& d : wipe_on_failure) {
        if ((prefix + d) == dir) {
            LOG(ERROR) << "Setting policy failed, deleting: " << dir;
            delete_dir_contents(dir);
            err = set_policy_on(fscrypt_key_ref, dir);
            break;
        }
    }
    return err;
}

static int parse_encryption_options_string(const std::string& options_string,
                                           std::string* contents_mode_ret,
                                           std::string* filenames_mode_ret,
                                           int* policy_version_ret) {
    auto parts = android::base::Split(options_string, ":");

    if (parts.size() != 3) {
        return -1;
    }

    *contents_mode_ret = parts[0];
    *filenames_mode_ret = parts[1];
    if (!android::base::StartsWith(parts[2], 'v') ||
        !android::base::ParseInt(&parts[2][1], policy_version_ret)) {
        return -1;
    }

    return 0;
}

// Set an encryption policy on the given directory.  The policy (key reference
// and encryption options) to use is read from files that were written by vold.
static int set_policy_on(const std::string& ref_basename, const std::string& dir) {
    std::string ref_filename = std::string("/data") + ref_basename;
    std::string key_ref;
    if (!android::base::ReadFileToString(ref_filename, &key_ref)) {
        LOG(ERROR) << "Unable to read system policy to set on " << dir;
        return -1;
    }

    auto options_filename = std::string("/data") + fscrypt_key_mode;
    std::string options_string;
    if (!android::base::ReadFileToString(options_filename, &options_string)) {
        LOG(ERROR) << "Cannot read encryption options string";
        return -1;
    }

    std::string contents_mode;
    std::string filenames_mode;
    int policy_version = 0;

    if (parse_encryption_options_string(options_string, &contents_mode, &filenames_mode,
                                        &policy_version)) {
        LOG(ERROR) << "Invalid encryption options string: " << options_string;
        return -1;
    }

    int result =
            fscrypt_policy_ensure(dir.c_str(), key_ref.c_str(), key_ref.length(),
                                  contents_mode.c_str(), filenames_mode.c_str(), policy_version);
    if (result) {
        LOG(ERROR) << android::base::StringPrintf("Setting %02x%02x%02x%02x policy on %s failed!",
                                                  key_ref[0], key_ref[1], key_ref[2], key_ref[3],
                                                  dir.c_str());
        return -1;
    }

    return 0;
}

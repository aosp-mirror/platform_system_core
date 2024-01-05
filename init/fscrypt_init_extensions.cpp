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
#include <logwrap/logwrap.h>

#define TAG "fscrypt"

using namespace android::fscrypt;

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

// Look up an encryption policy  The policy (key reference
// and encryption options) to use is read from files that were written by vold.
static bool LookupPolicy(const std::string& ref_basename, EncryptionPolicy* policy) {
    std::string ref_filename = std::string("/data") + ref_basename;
    if (!android::base::ReadFileToString(ref_filename, &policy->key_raw_ref)) {
        LOG(ERROR) << "Unable to read system policy with name " << ref_filename;
        return false;
    }

    auto options_filename = std::string("/data") + fscrypt_key_mode;
    std::string options_string;
    if (!android::base::ReadFileToString(options_filename, &options_string)) {
        LOG(ERROR) << "Cannot read encryption options string";
        return false;
    }
    if (!ParseOptions(options_string, &policy->options)) {
        LOG(ERROR) << "Invalid encryption options string: " << options_string;
        return false;
    }
    return true;
}

static bool EnsurePolicyOrLog(const EncryptionPolicy& policy, const std::string& dir) {
    if (!EnsurePolicy(policy, dir)) {
        std::string ref_hex;
        BytesToHex(policy.key_raw_ref, &ref_hex);
        LOG(ERROR) << "Setting " << ref_hex << " policy on " << dir << " failed!";
        return false;
    }
    return true;
}

static bool SetPolicyOn(const std::string& ref_basename, const std::string& dir) {
    EncryptionPolicy policy;
    if (!LookupPolicy(ref_basename, &policy)) return false;
    if (!EnsurePolicyOrLog(policy, dir)) return false;
    return true;
}

bool FscryptSetDirectoryPolicy(const std::string& ref_basename, FscryptAction action,
                               const std::string& dir) {
    if (action == FscryptAction::kNone) {
        return true;
    }
    if (SetPolicyOn(ref_basename, dir) || action == FscryptAction::kAttempt) {
        return true;
    }
    if (action == FscryptAction::kDeleteIfNecessary) {
        LOG(ERROR) << "Setting policy failed, deleting: " << dir;
        delete_dir_contents(dir);
        return SetPolicyOn(ref_basename, dir);
    }
    return false;
}

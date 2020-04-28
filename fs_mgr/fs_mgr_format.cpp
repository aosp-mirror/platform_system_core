/*
 * Copyright (C) 2015 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <errno.h>
#include <cutils/partition_utils.h>
#include <sys/mount.h>

#include <android-base/unique_fd.h>
#include <ext4_utils/ext4.h>
#include <ext4_utils/ext4_utils.h>
#include <logwrap/logwrap.h>
#include <selinux/android.h>
#include <selinux/label.h>
#include <selinux/selinux.h>

#include "fs_mgr_priv.h"
#include "cryptfs.h"

using android::base::unique_fd;

// Realistically, this file should be part of the android::fs_mgr namespace;
using namespace android::fs_mgr;

static int get_dev_sz(const std::string& fs_blkdev, uint64_t* dev_sz) {
    unique_fd fd(TEMP_FAILURE_RETRY(open(fs_blkdev.c_str(), O_RDONLY | O_CLOEXEC)));

    if (fd < 0) {
        PERROR << "Cannot open block device";
        return -1;
    }

    if ((ioctl(fd, BLKGETSIZE64, dev_sz)) == -1) {
        PERROR << "Cannot get block device size";
        return -1;
    }

    return 0;
}

static int format_ext4(const std::string& fs_blkdev, const std::string& fs_mnt_point,
                       bool crypt_footer) {
    uint64_t dev_sz;
    int rc = 0;

    rc = get_dev_sz(fs_blkdev, &dev_sz);
    if (rc) {
        return rc;
    }

    /* Format the partition using the calculated length */
    if (crypt_footer) {
        dev_sz -= CRYPT_FOOTER_OFFSET;
    }

    std::string size_str = std::to_string(dev_sz / 4096);
    const char* const mke2fs_args[] = {
            "/system/bin/mke2fs", "-t",   "ext4", "-b", "4096", fs_blkdev.c_str(),
            size_str.c_str(),     nullptr};

    rc = android_fork_execvp_ext(arraysize(mke2fs_args), const_cast<char**>(mke2fs_args), NULL,
                                 true, LOG_KLOG, true, nullptr, nullptr, 0);
    if (rc) {
        LERROR << "mke2fs returned " << rc;
        return rc;
    }

    const char* const e2fsdroid_args[] = {
            "/system/bin/e2fsdroid", "-e", "-a", fs_mnt_point.c_str(), fs_blkdev.c_str(), nullptr};

    rc = android_fork_execvp_ext(arraysize(e2fsdroid_args), const_cast<char**>(e2fsdroid_args),
                                 NULL, true, LOG_KLOG, true, nullptr, nullptr, 0);
    if (rc) {
        LERROR << "e2fsdroid returned " << rc;
    }

    return rc;
}

static int format_f2fs(const std::string& fs_blkdev, uint64_t dev_sz, bool crypt_footer) {
    if (!dev_sz) {
        int rc = get_dev_sz(fs_blkdev, &dev_sz);
        if (rc) {
            return rc;
        }
    }

    /* Format the partition using the calculated length */
    if (crypt_footer) {
        dev_sz -= CRYPT_FOOTER_OFFSET;
    }

    std::string size_str = std::to_string(dev_sz / 4096);
    // clang-format off
    const char* const args[] = {
        "/system/bin/make_f2fs",
        "-g", "android",
        fs_blkdev.c_str(),
        size_str.c_str(),
        nullptr
    };
    // clang-format on

    return android_fork_execvp_ext(arraysize(args), const_cast<char**>(args), NULL, true,
                                   LOG_KLOG, true, nullptr, nullptr, 0);
}

int fs_mgr_do_format(const FstabEntry& entry, bool crypt_footer) {
    LERROR << __FUNCTION__ << ": Format " << entry.blk_device << " as '" << entry.fs_type << "'";

    if (entry.fs_type == "f2fs") {
        return format_f2fs(entry.blk_device, entry.length, crypt_footer);
    } else if (entry.fs_type == "ext4") {
        return format_ext4(entry.blk_device, entry.mount_point, crypt_footer);
    } else {
        LERROR << "File system type '" << entry.fs_type << "' is not supported";
        return -EINVAL;
    }
}

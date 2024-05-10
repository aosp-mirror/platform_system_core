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

#include <android-base/properties.h>
#include <android-base/unique_fd.h>
#include <ext4_utils/ext4.h>
#include <ext4_utils/ext4_utils.h>
#include <logwrap/logwrap.h>
#include <selinux/android.h>
#include <selinux/label.h>
#include <selinux/selinux.h>
#include <string>

#include "fs_mgr_priv.h"

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
                       bool needs_projid, bool needs_metadata_csum) {
    uint64_t dev_sz;
    int rc = 0;

    rc = get_dev_sz(fs_blkdev, &dev_sz);
    if (rc) {
        return rc;
    }

    /* Format the partition using the calculated length */

    // EXT4 supports 4K block size on 16K page sizes. A 4K block
    // size formatted EXT4 partition will mount fine on both 4K and 16K page
    // size kernels.
    // However, EXT4 does not support 16K block size on 4K systems.
    // If we want the same userspace code to work on both 4k/16k kernels,
    // using a hardcoded 4096 block size is a simple solution. Using
    // getpagesize() here would work as well, but 4096 is simpler.
    std::string size_str = std::to_string(dev_sz / 4096);

    std::vector<const char*> mke2fs_args = {"/system/bin/mke2fs", "-t", "ext4", "-b", "4096"};

    // Project ID's require wider inodes. The Quotas themselves are enabled by tune2fs during boot.
    if (needs_projid) {
        mke2fs_args.push_back("-I");
        mke2fs_args.push_back("512");
    }
    // casefolding is enabled via tune2fs during boot.

    if (needs_metadata_csum) {
        mke2fs_args.push_back("-O");
        mke2fs_args.push_back("metadata_csum");
        // tune2fs recommends to enable 64bit and extent:
        //  Extents are not enabled.  The file extent tree can be checksummed,
        //  whereas block maps cannot. Not enabling extents reduces the coverage
        //  of metadata checksumming.  Re-run with -O extent to rectify.
        //  64-bit filesystem support is not enabled.  The larger fields afforded
        //  by this feature enable full-strength checksumming.  Run resize2fs -b to rectify.
        mke2fs_args.push_back("-O");
        mke2fs_args.push_back("64bit");
        mke2fs_args.push_back("-O");
        mke2fs_args.push_back("extent");
    }

    mke2fs_args.push_back(fs_blkdev.c_str());
    mke2fs_args.push_back(size_str.c_str());

    rc = logwrap_fork_execvp(mke2fs_args.size(), mke2fs_args.data(), nullptr, false, LOG_KLOG,
                             false, nullptr);
    if (rc) {
        LERROR << "mke2fs returned " << rc;
        return rc;
    }

    const char* const e2fsdroid_args[] = {
            "/system/bin/e2fsdroid", "-e", "-a", fs_mnt_point.c_str(), fs_blkdev.c_str(), nullptr};

    rc = logwrap_fork_execvp(arraysize(e2fsdroid_args), e2fsdroid_args, nullptr, false, LOG_KLOG,
                             false, nullptr);
    if (rc) {
        LERROR << "e2fsdroid returned " << rc;
    }

    return rc;
}

static int format_f2fs(const std::string& fs_blkdev, uint64_t dev_sz, bool needs_projid,
                       bool needs_casefold, bool fs_compress, bool is_zoned,
                       const std::vector<std::string>& user_devices) {
    if (!dev_sz) {
        int rc = get_dev_sz(fs_blkdev, &dev_sz);
        if (rc) {
            return rc;
        }
    }

    /* Format the partition using the calculated length */

    const auto size_str = std::to_string(dev_sz / getpagesize());
    std::string block_size = std::to_string(getpagesize());

    std::vector<const char*> args = {"/system/bin/make_f2fs", "-g", "android"};
    if (needs_projid) {
        args.push_back("-O");
        args.push_back("project_quota,extra_attr");
    }
    if (needs_casefold) {
        args.push_back("-O");
        args.push_back("casefold");
        args.push_back("-C");
        args.push_back("utf8");
    }
    if (fs_compress) {
        args.push_back("-O");
        args.push_back("compression");
        args.push_back("-O");
        args.push_back("extra_attr");
    }
    args.push_back("-w");
    args.push_back(block_size.c_str());
    args.push_back("-b");
    args.push_back(block_size.c_str());

    if (is_zoned) {
        args.push_back("-m");
    }
    for (auto& device : user_devices) {
        args.push_back("-c");
        args.push_back(device.c_str());
    }

    if (user_devices.empty()) {
        args.push_back(fs_blkdev.c_str());
        args.push_back(size_str.c_str());
    } else {
        args.push_back(fs_blkdev.c_str());
    }
    return logwrap_fork_execvp(args.size(), args.data(), nullptr, false, LOG_KLOG, false, nullptr);
}

int fs_mgr_do_format(const FstabEntry& entry) {
    LERROR << __FUNCTION__ << ": Format " << entry.blk_device << " as '" << entry.fs_type << "'";

    bool needs_casefold = false;
    bool needs_projid = true;

    if (entry.mount_point == "/data") {
        needs_casefold = android::base::GetBoolProperty("external_storage.casefold.enabled", false);
    }

    if (entry.fs_type == "f2fs") {
        return format_f2fs(entry.blk_device, entry.length, needs_projid, needs_casefold,
                           entry.fs_mgr_flags.fs_compress, entry.fs_mgr_flags.is_zoned,
                           entry.user_devices);
    } else if (entry.fs_type == "ext4") {
        return format_ext4(entry.blk_device, entry.mount_point, needs_projid,
                           entry.fs_mgr_flags.ext_meta_csum);
    } else {
        LERROR << "File system type '" << entry.fs_type << "' is not supported";
        return -EINVAL;
    }
}

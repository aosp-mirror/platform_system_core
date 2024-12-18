/*
 * Copyright (C) 2012 The Android Open Source Project
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

#include <chrono>
#include <string>

#include <android-base/logging.h>
#include <fs_mgr.h>
#include <fstab/fstab.h>

#include "libfstab/fstab_priv.h"

#define FS_MGR_TAG "[libfs_mgr] "

// Logs a message to kernel
#define LINFO    LOG(INFO) << FS_MGR_TAG
#define LWARNING LOG(WARNING) << FS_MGR_TAG
#define LERROR   LOG(ERROR) << FS_MGR_TAG
#define LFATAL LOG(FATAL) << FS_MGR_TAG

// Logs a message with strerror(errno) at the end
#define PINFO    PLOG(INFO) << FS_MGR_TAG
#define PWARNING PLOG(WARNING) << FS_MGR_TAG
#define PERROR   PLOG(ERROR) << FS_MGR_TAG
#define PFATAL PLOG(FATAL) << FS_MGR_TAG

#define CRYPTO_TMPFS_OPTIONS "size=512m,mode=0771,uid=1000,gid=1000"

/* fstab has the following format:
 *
 * Any line starting with a # is a comment and ignored
 *
 * Any blank line is ignored
 *
 * All other lines must be in this format:
 *   <source>  <mount_point> <fs_type> <mount_flags> <fs_options> <fs_mgr_options>
 *
 *   <mount_flags> is a comma separated list of flags that can be passed to the
 *                 mount command.  The list includes noatime, nosuid, nodev, nodiratime,
 *                 ro, rw, remount, defaults.
 *
 *   <fs_options> is a comma separated list of options accepted by the filesystem being
 *                mounted.  It is passed directly to mount without being parsed
 *
 *   <fs_mgr_options> is a comma separated list of flags that control the operation of
 *                     the fs_mgr program.  The list includes "wait", which will wait till
 *                     the <source> file exists, and "check", which requests that the fs_mgr
 *                     run an fscheck program on the <source> before mounting the filesystem.
 *                     If check is specifed on a read-only filesystem, it is ignored.
 *                     Also, "encryptable" means that filesystem can be encrypted.
 *                     The "encryptable" flag _MUST_ be followed by a = and a string which
 *                     is the location of the encryption keys.  It can either be a path
 *                     to a file or partition which contains the keys, or the word "footer"
 *                     which means the keys are in the last 16 Kbytes of the partition
 *                     containing the filesystem.
 *
 * When the fs_mgr is requested to mount all filesystems, it will first mount all the
 * filesystems that do _NOT_ specify check (including filesystems that are read-only and
 * specify check, because check is ignored in that case) and then it will check and mount
 * filesystem marked with check.
 *
 */

#define DM_BUF_SIZE 4096

using namespace std::chrono_literals;

bool fs_mgr_is_device_unlocked();

bool fs_mgr_is_f2fs(const std::string& blk_device);

bool fs_mgr_filesystem_available(const std::string& filesystem);
std::string fs_mgr_get_context(const std::string& mount_point);

namespace android {
namespace fs_mgr {

bool UnmapDevice(const std::string& name);

struct OverlayfsCheckResult {
    bool supported;
    std::string mount_flags;
};

OverlayfsCheckResult CheckOverlayfs();

}  // namespace fs_mgr
}  // namespace android

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

#include <errno.h>
#include <string.h>

#include <android-base/logging.h>
#include <sys/ioctl.h>

#include "fs_mgr_priv.h"
#include "fs_mgr_priv_dm_ioctl.h"

void fs_mgr_verity_ioctl_init(struct dm_ioctl *io,
                              const std::string &name,
                              unsigned flags)
{
    memset(io, 0, DM_BUF_SIZE);
    io->data_size = DM_BUF_SIZE;
    io->data_start = sizeof(struct dm_ioctl);
    io->version[0] = 4;
    io->version[1] = 0;
    io->version[2] = 0;
    io->flags = flags | DM_READONLY_FLAG;
    if (!name.empty()) {
        strlcpy(io->name, name.c_str(), sizeof(io->name));
    }
}

bool fs_mgr_create_verity_device(struct dm_ioctl *io,
                                 const std::string &name,
                                 int fd)
{
    fs_mgr_verity_ioctl_init(io, name, 1);
    if (ioctl(fd, DM_DEV_CREATE, io)) {
        ERROR("Error creating device mapping (%s)", strerror(errno));
        return false;
    }
    return true;
}

bool fs_mgr_destroy_verity_device(struct dm_ioctl *io,
                                  const std::string &name,
                                  int fd)
{
    fs_mgr_verity_ioctl_init(io, name, 0);
    if (ioctl(fd, DM_DEV_REMOVE, io)) {
        ERROR("Error removing device mapping (%s)", strerror(errno));
        return false;
    }
    return true;
}

bool fs_mgr_get_verity_device_name(struct dm_ioctl *io,
                                   const std::string &name,
                                   int fd,
                                   std::string *out_dev_name)
{
    FS_MGR_CHECK(out_dev_name != nullptr);

    fs_mgr_verity_ioctl_init(io, name, 0);
    if (ioctl(fd, DM_DEV_STATUS, io)) {
        ERROR("Error fetching verity device number (%s)", strerror(errno));
        return false;
    }

    int dev_num = (io->dev & 0xff) | ((io->dev >> 12) & 0xfff00);
    *out_dev_name = "/dev/block/dm-" + std::to_string(dev_num);

    return true;
}

bool fs_mgr_resume_verity_table(struct dm_ioctl *io,
                                const std::string &name,
                                int fd)
{
    fs_mgr_verity_ioctl_init(io, name, 0);
    if (ioctl(fd, DM_DEV_SUSPEND, io)) {
        ERROR("Error activating verity device (%s)", strerror(errno));
        return false;
    }
    return true;
}

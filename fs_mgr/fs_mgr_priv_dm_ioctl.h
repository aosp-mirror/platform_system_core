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

#ifndef __CORE_FS_MGR_PRIV_DM_IOCTL_H
#define __CORE_FS_MGR_PRIV_DM_IOCTL_H

#include <linux/dm-ioctl.h>
#include <string>

void fs_mgr_verity_ioctl_init(struct dm_ioctl* io, const std::string& name);

bool fs_mgr_create_verity_device(struct dm_ioctl* io, const std::string& name, int fd);

bool fs_mgr_destroy_verity_device(struct dm_ioctl* io, const std::string& name, int fd);

bool fs_mgr_get_verity_device_name(struct dm_ioctl* io, const std::string& name, int fd,
                                   std::string* out_dev_name);

bool fs_mgr_resume_verity_table(struct dm_ioctl* io, const std::string& name, int fd);

#endif /* __CORE_FS_MGR_PRIV_DM_IOCTL_H */

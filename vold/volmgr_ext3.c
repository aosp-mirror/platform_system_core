
/*
 * Copyright (C) 2008 The Android Open Source Project
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

#include "vold.h"
#include "volmgr.h"
#include "volmgr_ext3.h"

#define EXT3_DEBUG 0

int ext3_identify(blkdev_t *dev)
{
#if EXT3_DEBUG
    LOG_VOL("ext3_identify(%s):\n", dev->dev_fspath);
#endif
    return -ENOSYS;
}

int ext3_check(blkdev_t *dev)
{
#if EXT3_DEBUG
    LOG_VOL("ext3_check(%s):\n", dev->dev_fspath);
#endif
    return -ENOSYS;
}

int ext3_mount(blkdev_t *dev, volume_t *vol)
{
#if EXT3_DEBUG
    LOG_VOL("ext3_mount(%s, %s):\n", dev->dev_fspath, vol->mount_point);
#endif
    return -ENOSYS;
}

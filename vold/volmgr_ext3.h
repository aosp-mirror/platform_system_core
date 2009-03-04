
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

#ifndef _VOLMGR_EXT3_H
#define _VOLMGR_EXT3_H

#include "volmgr.h"
#include "blkdev.h"

int ext_identify(blkdev_t *blkdev);
int ext_check(blkdev_t *blkdev);
int ext_mount(blkdev_t *blkdev, volume_t *vol, boolean safe_mode);
#endif

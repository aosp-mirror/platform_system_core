/* libs/diskconfig/dump_diskconfig.c
 *
 * Copyright 2008, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "dump_diskconfig"
#include <stdio.h>

#include <cutils/log.h>

#include "diskconfig.h"

int
main(int argc, char *argv[])
{
    struct disk_info *dinfo;

    if (argc < 2) {
        ALOGE("usage: %s <conf file>", argv[0]);
        return 1;
    }

    if (!(dinfo = load_diskconfig(argv[1], NULL)))
        return 1;

    dump_disk_config(dinfo);

    return 0;
}


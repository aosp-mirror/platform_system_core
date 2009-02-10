
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

#include <fcntl.h>
#include <errno.h>

#include <linux/fs.h>

#include "vold.h"
#include "blkdev.h"
#include "format.h"
#include "diskmbr.h"
#include "logwrapper.h"

static char MKDOSFS_PATH[] = "/system/bin/mkdosfs";

int format_partition(blkdev_t *part)
{
    char *devpath;
    char *args[7];

    devpath = blkdev_get_devpath(part);

    args[0] = MKDOSFS_PATH;
    args[1] = "-F 32";
    args[2] = "-c 32";
    args[3] = "-n 2";
    args[4] = "-O android";
    args[5] = devpath;
    args[6] = NULL;

    int rc = logwrap(6, args);
 
    free(devpath);

    if (rc == 0) {
        LOG_VOL("Filesystem formatted OK\n");
        return 0;
    } else {
        LOGE("Format failed (unknokwn exit code %d)\n", rc);
        return -EIO;
    }
    return 0;
}

int initialize_mbr(blkdev_t *disk)
{
    int fd, rc;
    unsigned char block[512];
    struct dos_partition part;
    char *devpath;

    devpath = blkdev_get_devpath(disk);

    memset(&part, 0, sizeof(part));
    part.dp_flag = 0x80;
    part.dp_typ = 0xc;
    part.dp_start = ((1024 * 64) / 512) + 1;
    part.dp_size = disk->nr_sec - part.dp_start;

    memset(block, 0, sizeof(block));
    block[0x1fe] = 0x55;
    block[0x1ff] = 0xaa;

    dos_partition_enc(block + DOSPARTOFF, &part);

    if ((fd = open(devpath, O_RDWR)) < 0) {
        LOGE("Error opening disk file (%s)\n", strerror(errno));
        return -errno;
    }
    free(devpath);

    if (write(fd, block, sizeof(block)) < 0) {
        LOGE("Error writing MBR (%s)\n", strerror(errno));
        close(fd);
        return -errno;
    }

    if (ioctl(fd, BLKRRPART, NULL) < 0) {
        LOGE("Error re-reading partition table (%s)\n", strerror(errno));
        close(fd);
        return -errno;
    }
    close(fd);
    return 0;
}

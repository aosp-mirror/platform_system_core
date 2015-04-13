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
#include "ext4_utils.h"
#include "ext4.h"
#include "make_ext4fs.h"
#include "fs_mgr_priv.h"

extern struct fs_info info;     /* magic global from ext4_utils */
extern void reset_ext4fs_info();

static int format_ext4(char *fs_blkdev, char *fs_mnt_point)
{
    unsigned int nr_sec;
    int fd, rc = 0;

    if ((fd = open(fs_blkdev, O_WRONLY, 0644)) < 0) {
        ERROR("Cannot open block device.  %s\n", strerror(errno));
        return -1;
    }

    if ((ioctl(fd, BLKGETSIZE, &nr_sec)) == -1) {
        ERROR("Cannot get block device size.  %s\n", strerror(errno));
        close(fd);
        return -1;
    }

    /* Format the partition using the calculated length */
    reset_ext4fs_info();
    info.len = ((off64_t)nr_sec * 512);

    /* Use make_ext4fs_internal to avoid wiping an already-wiped partition. */
    rc = make_ext4fs_internal(fd, NULL, fs_mnt_point, 0, 0, 0, 0, 0, 0, 0, 0, NULL);
    if (rc) {
        ERROR("make_ext4fs returned %d.\n", rc);
    }
    close(fd);

    return rc;
}

static int format_f2fs(char *fs_blkdev)
{
    char * args[3];
    int pid;
    int rc = 0;

    args[0] = (char *)"/sbin/mkfs.f2fs";
    args[1] = fs_blkdev;
    args[2] = (char *)0;

    pid = fork();
    if (pid < 0) {
       return pid;
    }
    if (!pid) {
        /* This doesn't return */
        execv("/sbin/mkfs.f2fs", args);
        exit(1);
    }
    for(;;) {
        pid_t p = waitpid(pid, &rc, 0);
        if (p != pid) {
            ERROR("Error waiting for child process - %d\n", p);
            rc = -1;
            break;
        }
        if (WIFEXITED(rc)) {
            rc = WEXITSTATUS(rc);
            INFO("%s done, status %d\n", args[0], rc);
            if (rc) {
                rc = -1;
            }
            break;
        }
        ERROR("Still waiting for %s...\n", args[0]);
    }

    return rc;
}

int fs_mgr_do_format(struct fstab_rec *fstab)
{
    int rc = -EINVAL;

    ERROR("%s: Format %s as '%s'.\n", __func__, fstab->blk_device, fstab->fs_type);

    if (!strncmp(fstab->fs_type, "f2fs", 4)) {
        rc = format_f2fs(fstab->blk_device);
    } else if (!strncmp(fstab->fs_type, "ext4", 4)) {
        rc = format_ext4(fstab->blk_device, fstab->mount_point);
    } else {
        ERROR("File system type '%s' is not supported\n", fstab->fs_type);
    }

    return rc;
}

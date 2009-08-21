
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

#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>

#include <linux/fs.h>
#include <linux/msdos_fs.h>

#include "vold.h"
#include "blkdev.h"
#include "diskmbr.h"

#define DEBUG_BLKDEV 0

static blkdev_list_t *list_root = NULL;

static blkdev_t *_blkdev_create(blkdev_t *disk, char *devpath, int major,
                                int minor, char *type, struct media *media);

static int fat_valid_media(unsigned char media)
{                       
        return 0xf8 <= media || media == 0xf0;
}                               

char *blkdev_get_devpath(blkdev_t *blk)
{
    char *dp = malloc(256);
    sprintf(dp, "%s/vold/%d:%d", DEVPATH, blk->major, blk->minor);
    return dp;
}

int blkdev_refresh(blkdev_t *blk)
{
    int fd = 0;
    char *devpath = NULL;
    unsigned char *block = NULL;
    int i, rc;

    if (!(block = malloc(512)))
        goto out;

    /*
     * Get the device size
     */
    devpath = blkdev_get_devpath(blk);

    if ((fd = open(devpath, O_RDONLY)) < 0) {
        LOGE("Unable to open device '%s' (%s)", devpath, strerror(errno));
        return -errno;
    }

    if (ioctl(fd, BLKGETSIZE, &blk->nr_sec)) {
        LOGE("Unable to get device size (%s)", strerror(errno));
        return -errno;
    }
    close(fd);
    free(devpath);

    /*
     * Open the disk partition table
     */
    devpath = blkdev_get_devpath(blk->disk);
    if ((fd = open(devpath, O_RDONLY)) < 0) {
        LOGE("Unable to open device '%s' (%s)", devpath,
             strerror(errno));
        free(devpath);
        return -errno;
    }

    free(devpath);

    if ((rc = read(fd, block, 512)) != 512) {
        LOGE("Unable to read device partition table (%d, %s)",
             rc, strerror(errno));
        goto out;
    }

    /*
     * If we're a disk, then process the partition table. Otherwise we're
     * a partition so get the partition type
     */

    if (blk->type == blkdev_disk) {
        blk->nr_parts = 0;

        if ((block[0x1fe] != 0x55) || (block[0x1ff] != 0xAA)) {
            LOGI("Disk %d:%d does not contain a partition table",
                 blk->major, blk->minor);
            goto out;
        }

        for (i = 0; i < 4; i++) {
            struct dos_partition part;

            dos_partition_dec(block + DOSPARTOFF + i * sizeof(struct dos_partition), &part);
            if (part.dp_flag != 0 && part.dp_flag != 0x80) {
                struct fat_boot_sector *fb = (struct fat_boot_sector *) &block[0];
             
                if (!i && fb->reserved && fb->fats && fat_valid_media(fb->media)) {
                    LOGI("Detected FAT filesystem in partition table");
                    break;
                } else {
                    LOGI("Partition table looks corrupt");
                    break;
                }
            }
            if (part.dp_size != 0 && part.dp_typ != 0)
                blk->nr_parts++;
        }
    } else if (blk->type == blkdev_partition) {
        struct dos_partition part;
        int part_no = blk->minor -1;

        if (part_no < 4) {
            dos_partition_dec(block + DOSPARTOFF + part_no * sizeof(struct dos_partition), &part);
            blk->part_type = part.dp_typ;
        } else {
            LOGW("Skipping partition %d", part_no);
        }
    }

 out:

    if (block)
        free(block);

    char tmp[255];
    char tmp2[32];
    sprintf(tmp, "%s (blkdev %d:%d), %u secs (%u MB)",
                 (blk->type == blkdev_disk ? "Disk" : "Partition"),
                 blk->major, blk->minor,
                 blk->nr_sec,
                 (uint32_t) (((uint64_t) blk->nr_sec * 512) / 1024) / 1024);

    if (blk->type == blkdev_disk) 
        sprintf(tmp2, " %d partitions", blk->nr_parts);
    else
        sprintf(tmp2, " type 0x%x", blk->part_type);

    strcat(tmp, tmp2);
    LOGI(tmp);

    close(fd);

    return 0;
}

blkdev_t *blkdev_create(blkdev_t *disk, char *devpath, int major, int minor, struct media *media, char *type)
{
    return _blkdev_create(disk, devpath, major, minor, type, media);
}

static blkdev_t *_blkdev_create(blkdev_t *disk, char *devpath, int major,
                                int minor, char *type, struct media *media)
{
    blkdev_t *new;
    struct blkdev_list *list_entry;

    if (disk && disk->type != blkdev_disk) {
        LOGE("Non disk parent specified for blkdev!");
        return NULL;
    }

    if (!(new = malloc(sizeof(blkdev_t))))
        return NULL;

    memset(new, 0, sizeof(blkdev_t));

    if (!(list_entry = malloc(sizeof(struct blkdev_list)))) {
        free (new);
        return NULL;
    }
    list_entry->dev = new;
    list_entry->next = NULL;

    if (!list_root)
        list_root = list_entry;
    else {
        struct blkdev_list *list_scan = list_root;
        while (list_scan->next)
            list_scan = list_scan->next;
        list_scan->next = list_entry;
    }

    if (devpath)
        new->devpath = strdup(devpath);
    new->major = major;
    new->minor = minor;
    new->media = media;
    new->nr_sec = 0xffffffff;

    if (disk)
        new->disk = disk;
    else 
        new->disk = new; // Note the self disk pointer

    /* Create device nodes */
    char nodepath[255];
    mode_t mode = 0660 | S_IFBLK;
    dev_t dev = (major << 8) | minor;

    sprintf(nodepath, "%s/vold/%d:%d", DEVPATH, major, minor);
    if (mknod(nodepath, mode, dev) < 0) {
        LOGE("Error making device nodes for '%s' (%s)",
             nodepath, strerror(errno));
    }

    if (!strcmp(type, "disk"))
        new->type = blkdev_disk;
    else if (!strcmp(type, "partition"))
        new->type = blkdev_partition;
    else {
        LOGE("Unknown block device type '%s'", type);
        new->type = blkdev_unknown;
    }

    return new;
}

void blkdev_destroy(blkdev_t *blkdev)
{
    struct blkdev_list *list_next;

    if (list_root->dev == blkdev) {
        list_next = list_root->next;
        free (list_root);
        list_root = list_next;
    } else {
        struct blkdev_list *list_scan = list_root;
        while (list_scan->next->dev != blkdev)
            list_scan = list_scan -> next;
        list_next = list_scan->next->next;
        free(list_scan->next);
        list_scan->next = list_next;
    }

    if (blkdev->devpath)
        free(blkdev->devpath);

    char nodepath[255];
    sprintf(nodepath, "%s/vold/%d:%d", DEVPATH, blkdev->major, blkdev->minor);
    unlink(nodepath);

    free(blkdev);
}

blkdev_t *blkdev_lookup_by_path(char *devpath)
{
    struct blkdev_list *list_scan = list_root;

    while (list_scan) {
        if (!strcmp(list_scan->dev->devpath, devpath)) 
            return list_scan->dev;
        list_scan = list_scan->next;
    }
    return NULL;
}

blkdev_t *blkdev_lookup_by_devno(int maj, int min)
{
    struct blkdev_list *list_scan = list_root;

    while (list_scan) {
        if ((list_scan->dev->major == maj) &&
            (list_scan->dev->minor == min))
            return list_scan->dev;
        list_scan = list_scan->next;
    }
    return NULL;
}

/*
 * Given a disk device, return the number of partitions which 
 * have yet to be processed.
 */
int blkdev_get_num_pending_partitions(blkdev_t *blk)
{
    struct blkdev_list *list_scan = list_root;
    int num = blk->nr_parts;

    if (blk->type != blkdev_disk)
        return -EINVAL;

    while (list_scan) {
        if (list_scan->dev->type != blkdev_partition)
            goto next;

        if (list_scan->dev->major != blk->major)
            goto next;

        if (list_scan->dev->nr_sec != 0xffffffff &&
            list_scan->dev->devpath) {
            num--;
        }
 next:
        list_scan = list_scan->next;
    }
    return num;
}


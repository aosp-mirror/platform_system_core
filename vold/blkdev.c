
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

#include "vold.h"
#include "blkdev.h"
#include "diskmbr.h"

#define DEBUG_BLKDEV 0

static blkdev_list_t *list_root = NULL;

static blkdev_t *_blkdev_create(blkdev_t *disk, char *devpath, int major,
                                int minor, char *type, struct media *media, char *dev_fspath);
static void blkdev_dev_fspath_set(blkdev_t *blk, char *dev_fspath);

int blkdev_handle_devicefile_removed(blkdev_t *blk, char *dev_fspath)
{
#if DEBUG_BLKDEV
    LOG_VOL("blkdev_handle_devicefile_removed(%s):\n", dev_fspath);
#endif
    blkdev_dev_fspath_set(blk, NULL);
    return 0;
}

int blkdev_handle_devicefile_created(blkdev_t *blk, char *dev_fspath)
{
    int rc = 0;
    blkdev_t *disk;
 
#if DEBUG_BLKDEV
    LOG_VOL("blkdev_handle_devicefile_created(%s):\n", dev_fspath);
#endif

    if (!blk) {
        /*
         * This device does not yet have a backing blkdev associated with it.
         * Create a new one in the pending state and fill in the information
         * we have.
         */
        struct stat sbuf;

        if (stat(dev_fspath, &sbuf) < 0) {
            LOGE("Unable to stat device '%s' (%s)\n", dev_fspath, strerror(errno));
            return -errno;
        }

        int major = (sbuf.st_rdev & 0xfff00) >> 8;
        int minor = (sbuf.st_rdev & 0xff) | ((sbuf.st_rdev >> 12) & 0xfff00);

        disk = blkdev_lookup_by_devno(major, 0);

        if (!disk) {
            /*
             * If there isn't a disk associated with this device, then
             * its not what we're looking for
             */
#if DEBUG_BLKDEV
            LOG_VOL("Ignoring device file '%s' (no disk found)\n", dev_fspath);
#endif
            return 0;
        }

        if (!(blk = blkdev_create_pending_partition(disk, dev_fspath, major,
                                                    minor, disk->media))) {
            LOGE("Unable to create pending blkdev\n");
            return -1;
        }
    } else
        blkdev_dev_fspath_set(blk, dev_fspath);

    /*
     * If we're a disk, then read the partition table. Otherwise we're
     * a partition so get the partition type
     */
    disk = blk->disk;

    int fd;

    if ((fd = open(disk->dev_fspath, O_RDWR)) < 0) {
        LOGE("Unable to open device '%s' (%s)\n", disk->dev_fspath, strerror(errno));
        return -errno;
    }

    if (ioctl(fd, BLKGETSIZE, &blk->nr_sec)) {
        LOGE("Unable to get device size (%m)\n");
        return -errno;
    }

#if DEBUG_BLKDEV
    LOG_VOL("New device '%s' size = %u sectors\n", dev_fspath, blk->nr_sec);
#endif

    void *raw_pt;
    unsigned char *chr_pt;
    int i;

    raw_pt = chr_pt = mmap(NULL, 512, PROT_READ, MAP_PRIVATE, fd, 0);
    if (raw_pt == MAP_FAILED) {
        LOGE("Unable to mmap device paritition table (%m)\n");
        goto out_nommap;
    }

    if (blk->type == blkdev_disk) {
        blk->nr_parts = 0;

        if ((chr_pt[0x1fe] != 0x55) && (chr_pt[0x1ff] != 0xAA)) {
            LOG_VOL("Disk '%s' does not contain a partition table\n", dev_fspath);
            goto out;
        }

        for (i = 0; i < 4; i++) {
            struct dos_partition part;

            dos_partition_dec(raw_pt + DOSPARTOFF + i * sizeof(struct dos_partition), &part);
            if (part.dp_size != 0 && part.dp_typ != 0)
                blk->nr_parts++;
        }
        LOG_VOL("Disk device '%s' (blkdev %s) contains %d partitions\n",
                dev_fspath, blk->devpath, blk->nr_parts);
    } else if (blk->type == blkdev_partition) {
        struct dos_partition part;
        int part_no = blk->minor -1;

        dos_partition_dec(raw_pt + DOSPARTOFF + part_no * sizeof(struct dos_partition), &part);

        if (!part.dp_typ)
            LOG_VOL("Warning - Partition device '%s' (blkdev %s) has no partition type set\n",
                    dev_fspath, blk->devpath);
        blk->part_type = part.dp_typ;

        LOG_VOL("Partition device '%s' (blkdev %s) partition type 0x%x\n",
                 dev_fspath, blk->devpath, blk->part_type);
    } else {
        LOGE("Bad blkdev type '%d'\n", blk->type);
        rc = -EINVAL;
        goto out;
    }

 out:
    munmap(raw_pt, 512);
 out_nommap:
    close(fd);
    return rc;
}

blkdev_t *blkdev_create_pending_partition(blkdev_t *disk, char *dev_fspath, int major,
                                int minor, struct media *media)
{
    return _blkdev_create(disk, NULL, major, minor, "partition", media, dev_fspath);
}

blkdev_t *blkdev_create(blkdev_t *disk, char *devpath, int major, int minor, struct media *media, char *type)
{
    return _blkdev_create(disk, devpath, major, minor, type, media, NULL);
}

static blkdev_t *_blkdev_create(blkdev_t *disk, char *devpath, int major,
                                int minor, char *type, struct media *media, char *dev_fspath)
{
    blkdev_t *new;
    struct blkdev_list *list_entry;

    if (disk && disk->type != blkdev_disk) {
        LOGE("Non disk parent specified for blkdev!\n");
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
    if (dev_fspath)
        new->dev_fspath = strdup(dev_fspath);
    new->nr_sec = 0xffffffff;

    if (disk)
        new->disk = disk;
    else 
        new->disk = new; // Note the self disk pointer

    if (!strcmp(type, "disk"))
        new->type = blkdev_disk;
    else if (!strcmp(type, "partition"))
        new->type = blkdev_partition;
    else {
        LOGE("Unknown block device type '%s'\n", type);
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
    if (blkdev->dev_fspath)
        free(blkdev->dev_fspath);
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
#if DEBUG_BLKDEV
    LOG_VOL("blkdev_lookup_by_path(): No blkdev found @ %s\n", devpath);
#endif
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
#if DEBUG_BLKDEV
    LOG_VOL("blkdev_lookup_by_devno(): No blkdev found for %d.%d\n", maj, min);
#endif
    return NULL;
}

blkdev_t *blkdev_lookup_by_dev_fspath(char *dev_fspath)
{
    struct blkdev_list *list_scan = list_root;

    while (list_scan) {
        if (list_scan->dev->dev_fspath) {
            if (!strcmp(list_scan->dev->dev_fspath, dev_fspath)) 
                return list_scan->dev;
        }

        list_scan = list_scan->next;
    }
//    LOG_VOL("blkdev_lookup_by_devno(): No blkdev found for %d.%d\n", maj, min);
    return NULL;
}


/*
 * Given a disk device, return the number of partitions yet to be 
 * processed.
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

        if (list_scan->dev->nr_sec != 0xffffffff)
            num--;
 next:
        list_scan = list_scan->next;
    }
    return num;
}

void blkdev_devpath_set(blkdev_t *blk, char *devpath)
{
    blk->devpath = strdup(devpath);
}

static void blkdev_dev_fspath_set(blkdev_t *blk, char *dev_fspath)
{
    if (dev_fspath)
        blk->dev_fspath = strdup(dev_fspath);
    else {
        free(blk->dev_fspath);
        blk->dev_fspath = NULL;
    }
}

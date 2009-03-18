
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

#ifndef _BLKDEV_H
#define _BLKDEV_H

#include <sys/types.h>

struct media;

enum blk_type { blkdev_unknown, blkdev_disk, blkdev_partition };

struct blkdev {
    char          *devpath;
    enum blk_type type;
    struct media  *media;

    // If type == blkdev_disk then nr_parts = number of partitions
    int           nr_parts;

    // If type == blkdev_partition then part_type = partition type
    uint8_t       part_type;
    // If type == blkdev_partition
    struct blkdev *disk;

    unsigned int  nr_sec;

    int           major;
    int           minor;
};

struct blkdev_list {
    struct blkdev      *dev;
    struct blkdev_list *next;
};

typedef struct blkdev blkdev_t;
typedef struct blkdev_list blkdev_list_t;

blkdev_t *blkdev_create(blkdev_t *disk, char *devpath, int major, int minor, struct media *media, char *type);
blkdev_t *blkdev_create_pending_partition(blkdev_t *disk, char *dev_fspath, int major, int minor, struct media *media);
blkdev_t *blkdev_lookup_by_path(char *devpath);
blkdev_t *blkdev_lookup_by_devno(int maj, int min);
char *blkdev_get_devpath(blkdev_t *blk);

void blkdev_destroy(blkdev_t *blk);

int blkdev_get_num_pending_partitions(blkdev_t *blk);
int blkdev_refresh(blkdev_t *blk);
#endif

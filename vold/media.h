
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

#ifndef _MEDIA_H
#define _MEDIA_H

#include <sys/types.h>

#include "blkdev.h"

typedef enum media_type {
    media_unknown,
    media_mmc,
    media_devmapper,
} media_type_t;

/*
 * max 8 partitions per card
 */
#define MMC_PARTS_PER_CARD (1<<3)
#define ALIGN_MMC_MINOR(min) (min / MMC_PARTS_PER_CARD * MMC_PARTS_PER_CARD)

typedef struct media {
    char           *devpath;
    char           *name;
    uint32_t       serial;
    media_type_t   media_type;

    blkdev_list_t  *devs;
} media_t;

typedef struct media_list {
    media_t           *media;
    struct media_list *next;
} media_list_t;

media_t *media_create(char *devpath, char *name, char *serial, enum media_type);
media_t *media_lookup_by_path(char *devpath, boolean fuzzy_match);
media_t *media_lookup_by_dev(blkdev_t *dev);
void media_destroy(media_t *media);
int media_add_blkdev(media_t *media, blkdev_t *dev);
void media_remove_blkdev(media_t *media, blkdev_t *dev);
#endif

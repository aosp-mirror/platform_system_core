
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

#include <sys/types.h>

#include "vold.h"
#include "media.h"

static media_list_t *list_root = NULL;

media_t *media_create(char *devpath, char *name, char *serial, media_type_t type)
{
    media_list_t *list_entry;
    media_t *new;

    if (!(new = malloc(sizeof(media_t))))
        return NULL;

    memset(new, 0, sizeof(media_t));

    if (!(list_entry = malloc(sizeof(media_list_t)))) {
        free(new);
        return NULL;
    }
    list_entry->media = new;
    list_entry->next = NULL;

    if (!list_root)
        list_root = list_entry;
    else {
        media_list_t *list_scan = list_root;
        while(list_scan->next)
            list_scan = list_scan->next;
        list_scan->next = list_entry;
    }
     
    new->devpath = strdup(devpath);
    new->name = strdup(name);
    if (!serial)
        new->serial = 0;
    else
        new->serial = strtoul(serial, NULL, 0);

    new->media_type = type;

    return new;
}

void media_destroy(media_t *media)
{
    media_list_t *list_next;

    if (list_root->media == media) {
        list_next = list_root->next;
        free(list_root);
        list_root = list_next;
    } else {
        media_list_t *list_scan = list_root;
        while (list_scan->next->media != media)
            list_scan = list_scan -> next;
        list_next = list_scan->next->next;
        free(list_scan->next);
        list_scan->next = list_next;
    }

    free(media->devpath);
    free(media->name);

    while(media->devs)
        media_remove_blkdev(media, media->devs->dev);
    free(media);
}

media_t *media_lookup_by_path(char *devpath, boolean fuzzy_match)
{
    media_list_t *list_scan = list_root;

    while (list_scan) {
        if (fuzzy_match) {
            if (!strncmp(list_scan->media->devpath, devpath, strlen(devpath)))
                return list_scan->media;
        } else {
            if (!strcmp(list_scan->media->devpath, devpath))
                return list_scan->media;
        }
        list_scan = list_scan->next;
    }
#if DEBUG_MEDIA
    LOG_VOL("media_lookup_by_path(): No media found @ %s", devpath);
#endif
    return NULL;
}

int media_add_blkdev(media_t *card, blkdev_t *dev)
{
    blkdev_list_t *list_entry;

    if (!(list_entry = malloc(sizeof(blkdev_list_t))))
        return -ENOMEM;
    
    list_entry->next = NULL;
    list_entry->dev = dev;
    if (!card->devs)
        card->devs = list_entry;
    else {
        blkdev_list_t *scan = card->devs;

        while(scan->next)
            scan = scan->next;

        scan->next = list_entry;
    }
    return 0;
}

void media_remove_blkdev(media_t *card, blkdev_t *dev)
{
    if (card->devs->dev == dev)
        card->devs = card->devs->next;
    else {
        blkdev_list_t *scan = card->devs;
        while (scan->next->dev != dev)
            scan = scan -> next;
        blkdev_list_t *next = scan->next->next;
        free(scan->next);
        scan->next = next;
    }
}

media_t *media_lookup_by_dev(blkdev_t *dev)
{
    media_list_t *media_scan = list_root;

    while (media_scan) {
        blkdev_list_t *blk_scan = media_scan->media->devs;
        while (blk_scan) {
            if (blk_scan->dev == dev)
                return media_scan->media;
            blk_scan = blk_scan->next;
        }
        media_scan = media_scan->next;
    }
    return NULL;
}

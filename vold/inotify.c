
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
#include <errno.h>
#include <dirent.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/inotify.h>
#include <sys/stat.h>

#include "vold.h"
#include "inotify.h"
#include "blkdev.h"
#include "volmgr.h"

#define DEBUG_INOTIFY 0

static int handle_inotify_event(struct inotify_event *evt);

int process_inotify_event(int fd)
{
    char buffer[512];
    int len;
    int offset = 0;
  
    if ((len = read(fd, buffer, sizeof(buffer))) < 0) {
        LOGE("Unable to read inotify event (%m)\n");
        return -errno;
    }

    while (len >= (int) sizeof(struct inotify_event)) {
        struct inotify_event *evt = (struct inotify_event *) &buffer[offset];
   
        if (handle_inotify_event(evt) < 0)
            LOGE("Error handling inotify event (%m)\n");
      
        len -= sizeof(struct inotify_event) + evt->len;
        offset += sizeof(struct inotify_event) + evt->len;
         
    }
    return 0;
}

struct blk_dev_entry {
    int minor;
    char *name;
    struct blk_dev_entry *next;
};

int inotify_bootstrap(void)
{
    DIR *d;
    struct dirent *de;

    if (!(d = opendir(DEVPATH))) {
        LOGE("Unable to open directory '%s' (%m)\n", DEVPATH);
        return -errno;
    }

    struct blk_dev_entry *blkdevs[255];

    memset(blkdevs, 0, sizeof(blkdevs));

    while((de = readdir(d))) {
        char filename[255];
        struct stat sbuf;

        if (de->d_name[0] == '.')
            continue;

        sprintf(filename, "%s/%s", DEVPATH, de->d_name);

        if (stat(filename, &sbuf) < 0) {
            LOGE("Unable to stat '%s' (%m)\n", filename);
            continue;
        }

        if (!S_ISBLK(sbuf.st_mode))
            continue;


        int major = (sbuf.st_rdev & 0xfff00) >> 8;
        int minor = (sbuf.st_rdev & 0xff) | ((sbuf.st_rdev >> 12) & 0xfff00);

        struct blk_dev_entry *entry;

        if (!(entry = malloc(sizeof(struct blk_dev_entry)))) {
            LOGE("Out of memory\n");
            break;
        }
        entry->minor = minor;
        entry->name = strdup(de->d_name);
        entry->next = NULL;

        if (!blkdevs[major])
            blkdevs[major] = entry;
        else {
            struct blk_dev_entry *scan = blkdevs[major];

            /*
             * Insert the entry in minor number ascending order
             */
            while(scan) {
                if (minor < scan->minor) {
                    entry->next = scan;

                    if (scan == blkdevs[major])
                        blkdevs[major] = entry;
                    else
                        scan->next = entry;
                    break;
                }
                scan = scan->next;
            }
            if (!scan) {
                scan = blkdevs[major];
                while(scan->next)
                    scan = scan->next;
                scan->next = entry;
            }
        }

    }

    closedir(d);

    int i = 0;

    for (i = 0; i < 255; i++) {
        if (!blkdevs[i])
            continue;
        struct blk_dev_entry *scan = blkdevs[i];

        while(scan) {
            struct inotify_event *evt;
            int len;

            len = sizeof(struct inotify_event) + strlen(scan->name);

            if (!(evt = malloc(len))) {
                LOGE("Out of memory\n");
                break;
            }
            memset(evt, 0, len);
            strcpy(evt->name, scan->name);
            evt->mask = IN_CREATE;

            if (handle_inotify_event(evt) < 0)
                LOGE("Error handling bootstrapped inotify event (%m)\n");
            free(evt);

            scan = scan->next;
        }
    }

    for (i = 0; i < 255; i++) {
        if (!blkdevs[i])
            continue;

        if (!blkdevs[i]->next) {
            free(blkdevs[i]->name);
            free(blkdevs[i]);
            blkdevs[i] = NULL;
            continue;
        } 

        struct blk_dev_entry *scan = blkdevs[i];
        while(scan) {
            struct blk_dev_entry *next = scan->next->next;
              
            free(scan->next->name);
            free(scan->next);

            scan->next = next;
            scan = next;
        }

    } // for


    return 0;
}

static int handle_inotify_event(struct inotify_event *evt)
{
    char filename[255];
    int rc;

#if DEBUG_INOTIFY
    LOG_VOL("Inotify '%s' %s\n", evt->name, (evt->mask == IN_CREATE ? "created" : "deleted"));
#endif

    sprintf(filename, "%s%s", DEVPATH, evt->name);

    if (evt->mask == IN_CREATE) {
        struct stat sbuf;

        if (stat(filename, &sbuf) < 0) {
            LOGE("Unable to stat '%s' (%m)\n", filename);
            return -errno;
        }

        if (!S_ISBLK(sbuf.st_mode)) {
#if DEBUG_INOTIFY
            LOG_VOL("Ignoring inotify on '%s' (not a block device)\n", evt->name);
#endif
            return 0;
        }

        int major = (sbuf.st_rdev & 0xfff00) >> 8;
        int minor = (sbuf.st_rdev & 0xff) | ((sbuf.st_rdev >> 12) & 0xfff00);

        blkdev_t *blkdev = blkdev_lookup_by_devno(major, minor);

        if ((rc = blkdev_handle_devicefile_created(blkdev, filename)) < 0) {
            LOGE("Error handling device file '%s' creation (%s)\n", filename, strerror(rc));
            return rc;
        }
     
        if (!blkdev) {
#if DEBUG_INOTIFY
            LOG_VOL("No backing blkdev for '%s' available (yet) - pending volmgr dispatch\n", filename);
#endif
            return 0;
        }
 
#if DEBUG_INOTIFY
        LOG_VOL("NUM_PENDING_PARTITIONS = %d\n", blkdev_get_num_pending_partitions(blkdev));
#endif
        if (blkdev_get_num_pending_partitions(blkdev->disk) == 0) {
            if ((rc = volmgr_consider_disk(blkdev->disk)) < 0) {
                LOGE("Error from volmgr - %d\n", rc);
                return rc;
            }
        }
    } else {
        blkdev_t *blkdev;

        if (!(blkdev = blkdev_lookup_by_dev_fspath(filename))) {
#if DEBUG_INOTIFY
            LOG_VOL("Ignoring removal of '%s' (no backend blkdev)\n", filename);
#endif
            return 0;
        }

        if ((rc = blkdev_handle_devicefile_removed(blkdev, filename)) < 0) {
            LOGE("Error handling device file '%s' removal (%s)\n", filename, strerror(rc));
            return rc;
        }
    }

    return 0;
}


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
#include <sched.h>
#include <fcntl.h>

#include <sys/mount.h>

#include <linux/loop.h>

#include <cutils/config_utils.h>
#include <cutils/properties.h>

#include "vold.h"
#include "devmapper.h"

#define DEBUG_DEVMAPPER 1

static int loopback_start(struct devmapping *dm)
{
    int i;
    int fd;
    char filename[255];
    int rc;

#if DEBUG_DEVMAPPER
    LOG_VOL("loopback_start(%s):", dm->type_data.loop.loop_src);
#endif

    for (i = 0; i < MAX_LOOP; i++) {
        struct loop_info info;

        sprintf(filename, "/dev/block/loop%d", i);

        if ((fd = open(filename, O_RDWR)) < 0) {
            LOGE("Unable to open %s (%s)\n", filename, strerror(errno));
            return -errno;
        }

        rc = ioctl(fd, LOOP_GET_STATUS, &info);
        if (rc < 0 && errno == ENXIO)
            break;

        close(fd);

        if (rc < 0) {
            LOGE("Unable to get loop status for %s (%s)\n", filename,
                 strerror(errno));
            return -errno;
        }
    }

    if (i == MAX_LOOP) {
        LOGE("Out of loop devices\n");
        return -ENOSPC;
    }

    int file_fd;

    if ((file_fd = open(dm->type_data.loop.loop_src, O_RDWR)) < 0) {
        LOGE("Unable to open %s (%s)\n", dm->type_data.loop.loop_src,
             strerror(errno));
        return -errno;
    }

    if (ioctl(fd, LOOP_SET_FD, file_fd) < 0) {
        LOGE("Error setting up loopback interface (%s)\n", strerror(errno));
        return -errno;
    }

    dm->type_data.loop.loop_dev = strdup(filename);
    dm->type_data.loop.loop_no  = i;

    close(fd);
    close(file_fd);

#if DEBUG_DEVMAPPER
    LOG_VOL("Loop setup on %s for %s\n", dm->type_data.loop.loop_dev,
            dm->type_data.loop.loop_src);
#endif

    return 0;
}

int devmapper_start(struct devmapping *dm)
{
    int rc;
    char src_blkdev_path[255];

#if DEBUG_DEVMAPPER
    LOG_VOL("devmapper_start()");
#endif

    if (dm->src_type == dmsrc_loopback) {
       if ((rc = loopback_start(dm)) < 0)
           return rc;
    } else if (dm->src_type == dmsrc_partition) {
        LOGE("partition maps not yet supported");
        return -ENOSYS;
    } else {
        LOGE("devmapper_start(): Unsupported source type '%d'", dm->src_type);
        return -ENOENT;
    }

    /*
     * Configure the device mapper
     */

    return 0;
}

struct devmapping *devmapper_init(char *src, char *src_type, uint32_t size_mb,
                  char *target, char *params, char *tgt_fs)
{
    struct devmapping *dm;

    if (!(dm = malloc(sizeof(struct devmapping)))) {
        LOGE("devmapper_init(): out of memory");
        return NULL;
    }

    memset(dm, 0, sizeof(struct devmapping));

    if (!strcmp(src_type, "loopback_file")) {
        dm->src_type = dmsrc_loopback;
        dm->type_data.loop.loop_src = strdup(src);
    } else if (!strncmp(src_type, "partition ", strlen("partition "))) {
        dm->src_type = dmsrc_partition;
        char *p = strtok(src_type, " ");
        if (!p) {
            LOGE("Invalid partition specifier");
            goto out_free;
        }
        dm->type_data.part.part_type = strtoul(p, NULL, 0);
    } else {
        LOGE("Invalid src_type defined (%s)", src_type);
        goto out_free;
    }
    
    // XXX: Validate these
    dm->size_mb = size_mb;
    dm->target = strdup(target);
    dm->params = strdup(params);
    dm->tgt_fs = strdup(tgt_fs);

    return dm;
 out_free:
    return NULL;
}

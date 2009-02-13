
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
#include <linux/dm-ioctl.h>

#include <cutils/config_utils.h>
#include <cutils/properties.h>

#include "vold.h"
#include "devmapper.h"

#define DEBUG_DEVMAPPER 1

static void *_align(void *ptr, unsigned int a)
{
        register unsigned long agn = --a;

        return (void *) (((unsigned long) ptr + agn) & ~agn);
}

static struct dm_ioctl *_dm_ioctl_setup(struct devmapping *dm, int flags)
{
    void *buffer;
    void *p;
    const size_t min_size = 16 * 1024;
    size_t len = sizeof(struct dm_ioctl);
    struct dm_ioctl *io;
    struct dm_target_spec *tgt;
    int i;
    char params[1024];
    char key[80];

    key[0] = '\0';
    for (i = 0; i < (int) sizeof(dm->key); i++) {
        char tmp[8];

        sprintf(tmp, "%02x", dm->key[i]);
        strcat(key, tmp);
    }

    char srcdev[128];

    // XXX: Handle non crypt targets and non twofish (use param)
    if (dm->src_type == dmsrc_loopback)
        strcpy(srcdev, dm->type_data.loop.loop_dev);
    else if (dm->src_type == dmsrc_partition)
        strcpy(srcdev, dm->type_data.part.part_dev);

    sprintf(params, "twofish %s 0 %s 0", key, srcdev);

LOG_VOL("Params = '%s'", params);

    if (len < min_size)
        len = min_size;

    if (!(buffer = malloc(len))) {
        LOGE("out of memory");
        return NULL;
    }

    memset(buffer, 0, len);
    io = buffer;
    tgt = (struct dm_target_spec *) &buffer[sizeof(struct dm_ioctl)];

    io->version[0] = 4;
    io->version[1] = 0;
    io->version[2] = 0;

    io->data_size = len;
    io->data_start = sizeof(struct dm_ioctl);

    io->flags = flags;
    io->dev = 0;

    io->target_count = 1;
    io->event_nr = 1;
    strncpy(io->name, dm->target, sizeof(io->name));

    tgt->status = 0;
    tgt->sector_start = 0;
    tgt->length = (dm->size_mb * (1024 * 1024)) / 512;
    strncpy(tgt->target_type, "crypt", sizeof(tgt->target_type));

    p = buffer + sizeof(struct dm_ioctl) + sizeof(struct dm_target_spec);
    strcpy((char *) p, params);
    p+= strlen(params) + 1;

    p = _align(p, 8);
    tgt->next = p - buffer;

    return io;
}

static int get_next_available_dm()
{
    int i;

    for (i = 0; i < 8; i++) {
        char path[255];
        sprintf(path, "/dev/block/dm-%d", i);
        if ((access(path, F_OK) < 0) && (errno == ENOENT))
            return i;
    }

    LOGE("Out of device mapper numbers");
    return -1;
}

static int create_devmapping(struct devmapping *dm)
{
    struct dm_ioctl *io;
    int rc, fd;

#if DEBUG_DEVMAPPER
    LOG_VOL("create_devmapping():");
#endif

    if (dm->dm_no < 0) {
        LOGE("Invalid dm_no set");
        return -EINVAL;
    }

    if ((fd = open("/dev/device-mapper", O_RDWR)) < 0) {
        LOGE("Error opening device mapper (%d)", errno);
        return -errno;
    }

    if (!(io = _dm_ioctl_setup(dm, 0))) {
        LOGE("Unable to setup ioctl (out of memory)");
        close(fd);
        return -ENOMEM;
    }

    if ((rc = ioctl(fd, DM_DEV_CREATE, io)) < 0) {
        LOGE("device-mapper create ioctl failed (%d)", errno);
        rc = -errno;
        goto out_free;
    }

    free(io);

    if (!(io = _dm_ioctl_setup(dm, DM_STATUS_TABLE_FLAG))) {
        LOGE("Unable to setup ioctl (out of memory)");
        rc = -ENOMEM;
        goto out_nofree;
    }

    if ((rc = ioctl(fd, DM_TABLE_LOAD, io)) < 0) {
        LOGE("device-mapper load ioctl failed (%d)", errno);
        rc = -errno;
        goto out_free;
    }

    free(io);

    if (!(io = _dm_ioctl_setup(dm, 0))) {
        LOGE("Unable to setup ioctl (out of memory)");
        rc = -ENOMEM;
        goto out_nofree;
    }

    if ((rc = ioctl(fd, DM_DEV_SUSPEND, io)) < 0) {
        LOGE("device-mapper resume ioctl failed (%d)", errno);
        rc = -errno;
        goto out_free;
    }

out_free:
    free (io);
out_nofree:
    close (fd);
    return rc;
}

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
            LOGE("Unable to open %s (%s)", filename, strerror(errno));
            return -errno;
        }

        rc = ioctl(fd, LOOP_GET_STATUS, &info);
        if (rc < 0 && errno == ENXIO)
            break;

        close(fd);

        if (rc < 0) {
            LOGE("Unable to get loop status for %s (%s)", filename,
                 strerror(errno));
            return -errno;
        }
    }

    if (i == MAX_LOOP) {
        LOGE("Out of loop devices");
        return -ENOSPC;
    }

    int file_fd;

    if ((file_fd = open(dm->type_data.loop.loop_src, O_RDWR)) < 0) {
        LOGE("Unable to open %s (%s)", dm->type_data.loop.loop_src,
             strerror(errno));
        return -errno;
    }

    if (ioctl(fd, LOOP_SET_FD, file_fd) < 0) {
        LOGE("Error setting up loopback interface (%s)", strerror(errno));
        return -errno;
    }

    dm->type_data.loop.loop_dev = strdup(filename);
    dm->type_data.loop.loop_no  = i;

    close(fd);
    close(file_fd);

#if DEBUG_DEVMAPPER
    LOG_VOL("Loop setup on %s for %s", dm->type_data.loop.loop_dev,
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
    if ((rc = create_devmapping(dm)) < 0) {
        LOGE("Failed to create devmapping (%d)", rc);
        // XXX: if loopback then tear down
        return rc;
    }

    return 0;
}

struct devmapping *devmapper_init(char *src, char *src_type, uint32_t size_mb,
                  char *target, char *params, char *tgt_fs, char *mediapath)
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
    
    if ((dm->dm_no = get_next_available_dm()) < 0)
        goto out_free;

    sprintf(mediapath, "/devices/virtual/block/dm-%d", dm->dm_no);

    if (!(dm->media = media_create(mediapath,
                                   "unknown",
                                   "unknown",
                                   media_devmapper))) {
        LOGE("Unable to create media");
        goto out_free;
    }

    return dm;
 out_free:
    if (dm->target)
        free(dm->target);
    if (dm->params)
        free(dm->params);
    if (dm->tgt_fs)
        free(dm->tgt_fs);

    free(dm);
    return NULL;
}

int devmapper_genesis(struct devmapping *dm)
{

    if (dm->src_type == dmsrc_loopback) {
        int fd;

        LOG_VOL("devmapper_genesis(): Working on %s", 
                dm->type_data.loop.loop_src);

        unlink(dm->type_data.loop.loop_src);

        LOG_VOL("devmapper_genesis(): Creating imagefile (%u MB)",
                dm->size_mb);

        if ((fd = creat(dm->type_data.loop.loop_src, 0600)) < 0) {
            LOGE("Error creating imagefile (%s)", strerror(errno));
            return -errno;
        }

        if (ftruncate(fd, (dm->size_mb * (1024 * 1024))) < 0) {
            LOGE("Error truncating imagefile (%s)", strerror(errno));
            close(fd);
            return -errno;
        }
        close(fd);
    } else if (dm->src_type == dmsrc_partition) {
        LOGE("partition maps not yet supported");
        return -ENOSYS;
    }

    return devmapper_start(dm);
}

static int destroy_devmapping(struct devmapping *dm)
{
    struct dm_ioctl       *io;
    int                   dmFd;
    int                   rc = 0;

    LOG_VOL("destroy_devmapping():");

    if ((dmFd = open("/dev/device-mapper", O_RDWR)) < 0) {
        LOGE("Error opening device mapper (%d)", errno);
        return -errno;
    }

    if (!(io = _dm_ioctl_setup(dm, DM_PERSISTENT_DEV_FLAG))) {
        LOGE("Unable to setup ioctl (out of memory)");
        rc = -ENOMEM;
        goto out_nofree;
    }

    if ((rc = ioctl(dmFd, DM_DEV_REMOVE, io)) < 0) {
        LOGE("device-mapper remove ioctl failed (%d)", errno);
        rc = -errno;
        goto out_free;
    }

out_free:
    free (io);
out_nofree:
    close (dmFd);
    return rc;
}

static int loopback_stop(struct devmapping *dm)
{
    char devname[255];
    int device_fd;
    int rc = 0;

    LOG_VOL("loopback_stop():");

    device_fd = open(dm->type_data.loop.loop_dev, O_RDONLY);
    if (device_fd < 0) {
        LOG_ERROR("Failed to open loop (%d)", errno);
        return -errno;
    }

    if (ioctl(device_fd, LOOP_CLR_FD, 0) < 0) {
        LOG_ERROR("Failed to destroy loop (%d)", errno);
        rc = -errno;
    }

    close(device_fd);
    return rc;
}

int devmapper_stop(struct devmapping *dm)
{
    int rc;

    LOG_VOL("devmapper_stop():");

    if ((rc = destroy_devmapping(dm)))
        return rc;

    if (dm->src_type == dmsrc_loopback) {
        if ((rc = loopback_stop(dm)))
            return rc;
    } else if (dm->src_type == dmsrc_partition) {
        LOGE("partition maps not yet supported");
        return -ENOSYS;
    }
    return 0;
}

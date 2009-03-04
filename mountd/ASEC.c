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

/*
** Android Secure External Cache 
*/

#include "mountd.h"

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <dirent.h>
#include <ctype.h>
#include <pwd.h>
#include <stdlib.h>
#include <poll.h>
#include <errno.h>

#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>

#include <linux/dm-ioctl.h>
#include <linux/loop.h>

#include <cutils/properties.h>
#include <cutils/misc.h>

#include "ASEC.h"

//#define MODULE_FAILURE_IS_FATAL

extern int init_module(void *, unsigned long, const char *);
extern int delete_module(const char *, unsigned int);

struct asec_context
{
    char *name;           // Device mapper volume name
    char *srcPath;        // Path to the source (original) mount
    char *backingFile;    // Name of the image file
    unsigned int sectors; // Number of sectors
    char *dstPath;        // Destination mount point
    char *crypt;          // Crypt options

    boolean needs_format;
    boolean started;
    int cacheFd;
    int lo_num;
    int dm_num;
    unsigned char key[16];
};

static const char *MODULES[] = { "dm_mod", "crypto", "crypto_algapi", "crypto_blkcipher", 
                                 "cryptomgr", "dm_crypt", "jbd",  
                                 "twofish_common", "twofish", "cbc",
                                 "mbcache", "ext3",
                                 NULL };
static const char KEY_PATH[] = "/data/system/asec.key";
static const char MODULE_PATH[] = "/system/lib/modules";
static const char MKE2FS_PATH[] = "/system/bin/mke2fs";
static const char E2FSCK_PATH[] = "/system/bin/e2fsck";

boolean AsecIsStarted(void *Handle)
{
    struct asec_context *ctx = (struct asec_context *) Handle;

    return ctx->started;
}

const char *AsecMountPoint(void *Handle)
{
    struct asec_context *ctx = (struct asec_context *) Handle;

    return ctx->dstPath;
}

static boolean AsecIsEnabled()
{
    char value[PROPERTY_VALUE_MAX];
    int  enabled;

    property_get(ASEC_ENABLED, value, "0");

    if (atoi(value) == 1)
        return true;
    return false;
}

void *AsecInit(const char *Name, const char *SrcPath, const char *BackingFile,
               const char *Size, const char *DstPath, const char *Crypt)
{
    struct asec_context *ctx;

    if (!AsecIsEnabled())
        return NULL;

    LOG_ASEC("AsecInit(%s, %s, %s, %s, %s, %s):\n",
             Name, SrcPath, BackingFile, Size, DstPath, Crypt);

    if (!Name || !SrcPath || !BackingFile || !Size || !DstPath || !Crypt) {
        LOG_ERROR("AsecInit(): Invalid arguments\n");
        return NULL;
    }

    if (!(ctx = malloc(sizeof(struct asec_context)))) {
        LOG_ERROR("AsecInit(): Out of memory\n");
        return NULL;
    }

    memset(ctx, 0, sizeof(struct asec_context));
    ctx->name = strdup(Name);
    ctx->srcPath = strdup(SrcPath);
    ctx->backingFile = strdup(BackingFile);
    ctx->sectors = atoi(Size);
    ctx->dstPath = strdup(DstPath);
    ctx->crypt = strdup(Crypt);
    return ctx;
}

void AsecDeinit(void *Handle)
{
    struct asec_context *ctx = (struct asec_context *) Handle;

    free(ctx->name);
    free(ctx->srcPath);
    free(ctx->backingFile);
    free(ctx->dstPath);
    free(ctx->crypt);

    free(ctx);
}

static int AsecLoadModules()
{
    int i;

    for (i = 0; MODULES[i] != NULL; i++) {
	const char *moduleName = MODULES[i];
        char moduleFile[255];
        int rc = 0;
        void *module;
        unsigned int size;

        sprintf(moduleFile, "%s/%s.ko", MODULE_PATH, moduleName);
        module = load_file(moduleFile, &size);
        if (!module) {
            LOG_ERROR("Failed to load module %s (%d)\n", moduleFile, errno);
            return -1;
        }

        rc = init_module(module, size, "");
        free(module);
        if (rc && errno != EEXIST) {
            LOG_ERROR("Failed to init module %s (%d)\n", moduleFile, errno);
            return -errno;
        }
    }
    return 0;
}

static int AsecUnloadModules()
{
    int i, j, rc;

    for (i = 0; MODULES[i] != NULL; i++);

    for (j = (i - 1); j >= 0; j--) {
	const char *moduleName = MODULES[j];
        int maxretry = 10;
        while(maxretry-- > 0) {
            rc = delete_module(moduleName, O_NONBLOCK | O_EXCL);
            if (rc < 0 && errno == EAGAIN)
                usleep(500000);
            else
                break;
        }
        if (rc != 0) {
            LOG_ERROR("Failed to unload module %s\n", moduleName);
            return -errno;
        }
    }
    return 0;
}

static int AsecGenerateKey(struct asec_context *ctx)
{
    LOG_ASEC("AsecGenerateKey():\n");

    memset((void *) ctx->key, 0x69, sizeof(ctx->key));
    return 0;
}

static int AsecLoadGenerateKey(struct asec_context *ctx)
{
    int fd;
    int rc = 0;

    if ((fd = open(KEY_PATH, O_RDWR | O_CREAT, 0600)) < 0) {
        LOG_ERROR("Error opening / creating keyfile (%d)\n", errno);
        return -errno;
    }

    if (read(fd, ctx->key, sizeof(ctx->key)) != sizeof(ctx->key)) {
        LOG_ASEC("Generating key\n");
        if ((rc = AsecGenerateKey(ctx)) < 0) {
            LOG_ERROR("Error generating key (%d)\n", rc);
            goto out;
        }
        if (write(fd, ctx->key, sizeof(ctx->key)) != sizeof(ctx->key)) {
            LOG_ERROR("Error writing keyfile (%d)\n", errno);
            rc = -1;
            goto out;
        }
    }
    
 out:
    close (fd);
    return rc;
}

static int AsecFormatFilesystem(struct asec_context *ctx)
{
    char cmdline[255];
    int rc;

    sprintf(cmdline,
            "%s -b 4096 -m 1 -j -L \"%s\" /dev/block/dm-%d",
            MKE2FS_PATH, ctx->name, ctx->dm_num);

    LOG_ASEC("Formatting filesystem (%s)\n", cmdline);
    // XXX: PROTECT FROM VIKING KILLER
    if ((rc = system(cmdline)) < 0) {
        LOG_ERROR("Error executing format command (%d)\n", errno);
        return -errno;
    }

    rc = WEXITSTATUS(rc);

    if (!rc) {
        LOG_ASEC("Format completed\n");
    } else {
        LOG_ASEC("Format failed (%d)\n", rc);
    }

    return rc;
}

static int AsecCheckFilesystem(struct asec_context *ctx)
{
    char cmdline[255];
    int rc;

    sprintf(cmdline, "%s -p /dev/block/dm-%d", E2FSCK_PATH, ctx->dm_num);

    LOG_ASEC("Checking filesystem (%s)\n", cmdline);
    // XXX: PROTECT FROM VIKING KILLER
    if ((rc = system(cmdline)) < 0) {
        LOG_ERROR("Error executing check command (%d)\n", errno);
        return -errno;
    }

    rc = WEXITSTATUS(rc);

    if (rc == 0) {
        LOG_ASEC("ASEC volume '%s' had no errors\n", ctx->name);
    } else if (rc == 1) {
        LOG_ASEC("ASEC volume '%s' had corrected errors\n", ctx->name);
        rc = 0;
    } else if (rc == 2) {
        LOG_ERROR("ASEC volume '%s' had corrected errors (system should be rebooted)\n", ctx->name);
    } else if (rc == 4) {
        LOG_ERROR("ASEC volume '%s' had uncorrectable errors\n", ctx->name);
    } else if (rc == 8) {
        LOG_ERROR("Operational error while checking volume '%s'\n", ctx->name);
    } else {
        LOG_ERROR("Unknown e2fsck exit code (%d)\n", rc);
    }
    return rc;
}

static int AsecOpenCreateCache(struct asec_context *ctx)
{
    char filepath[255];

    sprintf(filepath, "%s/%s", ctx->srcPath, ctx->backingFile);

    if ((ctx->cacheFd = open(filepath, O_RDWR)) < 0) {
        if (errno == ENOENT) {
            int rc = 0;

            LOG_ASEC("Creating cache file (%u sectors)\n", ctx->sectors);
            if ((ctx->cacheFd = creat(filepath, 0600)) < 0) {
                LOG_ERROR("Error creating cache (%d)\n", errno);
                return -errno;
            }
            if (ftruncate(ctx->cacheFd, ctx->sectors * 512) < 0) {
                LOG_ERROR("Error truncating cache (%d)\n", errno);
                close(ctx->cacheFd);
                unlink(filepath);
                return -errno;
            }
            LOG_ASEC("Cache created (%u sectors) \n", ctx->sectors);
            close(ctx->cacheFd); // creat() is WRONLY
           
            if ((ctx->cacheFd = open(filepath, O_RDWR)) < 0) {
               LOG_ERROR("Error opening cache file (%d)\n", errno);
                close(ctx->cacheFd);
                unlink(filepath);
                return -errno;
            }

            ctx->needs_format = 1;
        } else
            return -errno;
    } else {
        struct stat stat_buf;

        if (fstat(ctx->cacheFd, &stat_buf) < 0) {
            LOG_ERROR("Failed to fstat cache (%d)\n", errno);
            close(ctx->cacheFd);
            return -errno;
        }
        if (stat_buf.st_size != ctx->sectors * 512) {
            LOG_ERROR("Cache size %lld != configured size %u\n",
                      stat_buf.st_size, ctx->sectors * 512);
        }

        // XXX: Verify volume label matches ctx->name
    }

    return 0;
}

static void AsecCloseCache(struct asec_context *ctx)
{
    close(ctx->cacheFd);
}

static void *_align(void *ptr, unsigned int a)
{
        register unsigned long agn = --a;

        return (void *) (((unsigned long) ptr + agn) & ~agn);
}

static struct dm_ioctl *_dm_ioctl_setup(struct asec_context *ctx, int flags)
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

    for (i = 0; i < (int) sizeof(ctx->key); i++) {
        char tmp[8];

        sprintf(tmp, "%02x", ctx->key[i]);
        strcat(key, tmp);
    }

    // XXX: Handle ctx->crypt 
    sprintf(params, "twofish %s 0 /dev/block/loop%d 0", key, ctx->lo_num);
 
    if (len < min_size)
        len = min_size;

    if (!(buffer = malloc(len))) {
        LOG_ERROR("Unable to allocate memory\n");
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
    strncpy(io->name, ctx->name, sizeof(io->name));

    tgt->status = 0;
    tgt->sector_start = 0;
    tgt->length = ctx->sectors;
    strncpy(tgt->target_type, "crypt", sizeof(tgt->target_type));

    p = buffer + sizeof(struct dm_ioctl) + sizeof(struct dm_target_spec);
    strcpy((char *) p, params);
    p+= strlen(params) + 1;

    p = _align(p, 8);
    tgt->next = p - buffer;

    return io;
}

static int FindNextAvailableDm()
{
    int i;

    for (i = 0; i < 8; i++) {
        char path[255];
        sprintf(path, "/dev/block/dm-%d", i);
        if ((access(path, F_OK) < 0) && (errno == ENOENT))
            return i;
    }

    LOG_ERROR("Out of device mapper numbers\n");
    return -1;
}

static int AsecCreateDeviceMapping(struct asec_context *ctx)
{
    struct dm_ioctl       *io;
    int                   dmFd;
    int                   rc = 0;

    ctx->dm_num = FindNextAvailableDm();

    if ((dmFd = open("/dev/device-mapper", O_RDWR)) < 0) {
        LOG_ERROR("Error opening device mapper (%d)\n", errno);
        return -errno;
    }

    if (!(io = _dm_ioctl_setup(ctx, 0))) {
        LOG_ERROR("Unable to setup ioctl (out of memory)\n");
        close(dmFd);
        return -ENOMEM;
    }

    if ((rc = ioctl(dmFd, DM_DEV_CREATE, io)) < 0) {
        LOG_ERROR("device-mapper create ioctl failed (%d)\n", errno);
        rc = -errno;
        goto out_free;
    } 

    free(io);

    if (!(io = _dm_ioctl_setup(ctx, DM_STATUS_TABLE_FLAG))) {
        LOG_ERROR("Unable to setup ioctl (out of memory)\n");
        rc = -ENOMEM;
        goto out_nofree;
    }
 
    if ((rc = ioctl(dmFd, DM_TABLE_LOAD, io)) < 0) {
        LOG_ERROR("device-mapper load ioctl failed (%d)\n", errno);
        rc = -errno;
        goto out_free;
    }

    free(io);
 
    if (!(io = _dm_ioctl_setup(ctx, 0))) {
        LOG_ERROR("Unable to setup ioctl (out of memory)\n");
        rc = -ENOMEM;
        goto out_nofree;
    }

    if ((rc = ioctl(dmFd, DM_DEV_SUSPEND, io)) < 0) {
        LOG_ERROR("device-mapper resume ioctl failed (%d)\n", errno);
        rc = -errno;
        goto out_free;
    }

out_free:
    free (io);
out_nofree:
    close (dmFd);
    return rc;
}

static int AsecDestroyDeviceMapping(struct asec_context *ctx)
{
    struct dm_ioctl       *io;
    int                   dmFd;
    int                   rc = 0;

    if ((dmFd = open("/dev/device-mapper", O_RDWR)) < 0) {
        LOG_ERROR("Error opening device mapper (%d)\n", errno);
        return -errno;
    }

    if (!(io = _dm_ioctl_setup(ctx, DM_PERSISTENT_DEV_FLAG))) {
        LOG_ERROR("Unable to setup ioctl (out of memory)\n");
        rc = -ENOMEM;
        goto out_nofree;
    }

    if ((rc = ioctl(dmFd, DM_DEV_REMOVE, io)) < 0) {
        LOG_ERROR("device-mapper remove ioctl failed (%d)\n", errno);
        rc = -errno;
        goto out_free;
    } 

out_free:
    free (io);
out_nofree:
    close (dmFd);
    return rc;
}

static int AsecMountCache(struct asec_context *ctx)
{
    int flags = MS_NODEV | MS_NOEXEC | MS_NOSUID | MS_NOATIME | MS_NODIRATIME;
    char devname[255];

    if (access(ctx->dstPath, R_OK)) {
        LOG_ERROR("Destination mount point '%s' unavailable (%d)\n", ctx->dstPath, errno);
        return -errno;
    }

    sprintf(devname, "/dev/block/dm-%d", ctx->dm_num);

    if (mount(devname, ctx->dstPath, "ext3", flags, NULL)) {
        LOG_ERROR("ASEC mount failed (%d)\n", errno);
        return -errno;
    }
    
    return 0;
}

static int AsecUnmountCache(struct asec_context *ctx)
{
    if (umount(ctx->dstPath)) {
        if (errno == EBUSY) {
            LOG_ASEC("ASEC volume '%s' still busy\n", ctx->name);
        } else {
            LOG_ERROR("ASEC umount failed (%d)\n", errno);
        }
        return -errno;
    }
    LOG_ASEC("ASEC volume '%s' unmounted\n", ctx->name);
    return 0;
}

static int FindNextAvailableLoop()
{
    int i;

    for (i = 0; i < MAX_LOOP; i++) {
        struct loop_info info;
        char devname[255];
        int fd;

        sprintf(devname, "/dev/block/loop%d", i);

        if ((fd = open(devname, O_RDONLY)) < 0) {
            LOG_ERROR("Unable to open %s (%d)\n", devname, errno);
            return -errno;
        }

        if (ioctl(fd, LOOP_GET_STATUS, &info) < 0) {
            close(fd);

            if (errno == ENXIO)
                return i;

            LOG_ERROR("Unable to get loop status for %s (%d)\n", devname, errno);
            return -errno;
        }
        close(fd);
    }
    return -ENXIO;
}

static int AsecCreateLoop(struct asec_context *ctx)
{
    char devname[255];
    int device_fd;
    int rc = 0;

    ctx->lo_num = FindNextAvailableLoop();
    if (ctx->lo_num < 0) {
        LOG_ERROR("No loop devices available\n");
        return -ENXIO;
    }

    sprintf(devname, "/dev/block/loop%d", ctx->lo_num);
    device_fd = open(devname, O_RDWR);
    if (device_fd < 0) {
        LOG_ERROR("failed to open loop device (%d)\n", errno);
        return -errno;
    }

    if (ioctl(device_fd, LOOP_SET_FD, ctx->cacheFd) < 0) {
        LOG_ERROR("loop_set_fd ioctl failed (%d)\n", errno);
        rc = -errno;
    }
    close(device_fd);
    return rc;
}

static int AsecDestroyLoop(struct asec_context *ctx)
{
    char devname[255];
    int device_fd;
    int rc = 0;

    sprintf(devname, "/dev/block/loop%d", ctx->lo_num);
    device_fd = open(devname, O_RDONLY);
    if (device_fd < 0) {
        LOG_ERROR("Failed to open loop (%d)\n", errno);
        return -errno;
    }

    if (ioctl(device_fd, LOOP_CLR_FD, 0) < 0) {
        LOG_ERROR("Failed to destroy loop (%d)\n", errno);
        rc = -errno;
    }

    close(device_fd);
    return rc;
}

int AsecStart(void *Handle)
{
    struct asec_context *ctx = (struct asec_context *) Handle;
    char value[PROPERTY_VALUE_MAX];
    int rc = 0;

    if (!ctx)
        return -EINVAL;

    if (ctx->started)
        return -EBUSY;

    LOG_ASEC("AsecStart(%s):\n", ctx->name);

    NotifyAsecState(ASEC_BUSY, ctx->dstPath);

    if ((rc = AsecLoadModules()) < 0) {
        LOG_ERROR("AsecStart: Failed to load kernel modules\n");
#ifdef MODULE_FAILURE_IS_FATAL
        NotifyAsecState(ASEC_FAILED_INTERR, ctx->dstPath);
	return rc;
#endif
    }

    if ((rc = AsecLoadGenerateKey(ctx))) {
        LOG_ERROR("AsecStart: Failed to load / generate key\n");
        NotifyAsecState(ASEC_FAILED_INTERR, ctx->dstPath);
	return rc;
    }
    
    if ((rc = AsecOpenCreateCache(ctx)) < 0) {
        LOG_ERROR("AsecStart: Failed to open / create cache\n");
        NotifyAsecState(ASEC_FAILED_INTERR, ctx->dstPath);
	return rc;
    }

    if ((rc = AsecCreateLoop(ctx)) < 0) {
        LOG_ERROR("AsecStart: Failed to create loop\n");
        NotifyAsecState(ASEC_FAILED_INTERR, ctx->dstPath);
	goto fail_closecache;
    }

    if ((rc = AsecCreateDeviceMapping(ctx)) < 0) {
        LOG_ERROR("AsecStart: Failed to create devmapping (%d)\n", rc);
        NotifyAsecState(ASEC_FAILED_INTERR, ctx->dstPath);
        goto fail_destroyloop;
    }
    
    if (ctx->needs_format) {
        if ((rc = AsecFormatFilesystem(ctx))) {
            LOG_ERROR("AsecStart: Failed to format cache (%d)\n", rc);
            NotifyAsecState(ASEC_FAILED_INTERR, ctx->dstPath);
            goto fail_destroydm;
        }
        ctx->needs_format = 0;
    } else {
        if ((rc = AsecCheckFilesystem(ctx))) {
            LOG_ERROR("AsecStart: Failed to check filesystem (%d)\n", rc);
            NotifyAsecState(ASEC_FAILED_INTERR, ctx->dstPath);
            goto fail_destroydm;
        }
    }

    if ((rc = AsecMountCache(ctx)) < 0) {
        LOG_ERROR("AsecStart: Failed to mount cache (%d)\n", rc);
        NotifyAsecState(ASEC_FAILED_INTERR, ctx->dstPath);
        goto fail_destroydm;
    }
    
    NotifyAsecState(ASEC_AVAILABLE, ctx->dstPath);
    ctx->started = true;

    return rc;

 fail_destroydm:
    AsecDestroyDeviceMapping(ctx);
 fail_destroyloop:
    AsecDestroyLoop(ctx);
 fail_closecache:
    AsecCloseCache(ctx);
    return rc;
}

int AsecStop(void *Handle)
{
    struct asec_context *ctx = (struct asec_context *) Handle;
    int rc = 0;

    if (!ctx->started)
        return -EINVAL;

    LOG_ASEC("AsecStop(%s):\n", ctx->name);

    NotifyAsecState(ASEC_BUSY, ctx->dstPath);

    if ((rc = AsecUnmountCache(ctx)) < 0) {
        LOG_ERROR("AsecStop: Failed to unmount cache (%d)\n", rc);
        NotifyAsecState(ASEC_FAILED_INTERR, ctx->dstPath);
	return rc;
    }

    if ((rc = AsecDestroyDeviceMapping(ctx)) < 0) {
        LOG_ERROR("AsecStop: Failed to destroy devmapping (%d)\n", rc);
        NotifyAsecState(ASEC_FAILED_INTERR, ctx->dstPath);
	return rc;
    }

    if ((rc = AsecDestroyLoop(ctx)) < 0) {
        LOG_ERROR("AsecStop: Failed to destroy loop device (%d)\n", rc);
        NotifyAsecState(ASEC_FAILED_INTERR, ctx->dstPath);
	return rc;
    }

    AsecCloseCache(ctx);
 
    if ((rc = AsecUnloadModules()) < 0) {
        if (rc == -EAGAIN) {
            LOG_ASEC("AsecStop: Kernel modules still in use\n");
        } else {
            LOG_ERROR("AsecStop: Failed to unload kernel modules (%d)\n", rc);
#ifdef MODULE_FAILURE_IS_FATAL
            NotifyAsecState(ASEC_FAILED_INTERR, ctx->dstPath);
	    return rc;
#endif
        }
    }

    ctx->started = false;
    NotifyAsecState(ASEC_DISABLED, ctx->dstPath);
    return rc;
}

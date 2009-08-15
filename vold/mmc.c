
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
#include "mmc.h"
#include "media.h"
#include "diskmbr.h" /* for NDOSPART */

#define DEBUG_BOOTSTRAP 0

static int mmc_bootstrap_controller(char *sysfs_path);
static int mmc_bootstrap_card(char *sysfs_path);
static int mmc_bootstrap_block(char *devpath);
static int mmc_bootstrap_mmcblk(char *devpath);
static int mmc_bootstrap_mmcblk_partition(char *devpath);

/*
 * Bootstrap our mmc information.
 */
int mmc_bootstrap()
{
    DIR *d;
    struct dirent *de;

    if (!(d = opendir(SYSFS_CLASS_MMC_PATH))) {
        LOG_ERROR("Unable to open '%s' (%s)", SYSFS_CLASS_MMC_PATH,
                  strerror(errno));
        return -errno;
    }

    while ((de = readdir(d))) {
        char tmp[255];

        if (de->d_name[0] == '.')
            continue;

        sprintf(tmp, "%s/%s", SYSFS_CLASS_MMC_PATH, de->d_name);
        if (mmc_bootstrap_controller(tmp)) {
            LOG_ERROR("Error bootstrapping controller '%s' (%s)", tmp,
                      strerror(errno));
        }
    }

    closedir(d);

    return 0;
}

static int mmc_bootstrap_controller(char *sysfs_path)
{
    DIR *d;
    struct dirent *de;

#if DEBUG_BOOTSTRAP
    LOG_VOL("bootstrap_controller(%s):", sysfs_path);
#endif
    if (!(d = opendir(sysfs_path))) {
        LOG_ERROR("Unable to open '%s' (%s)", sysfs_path, strerror(errno));
        return -errno;
    }

    while ((de = readdir(d))) {
        char tmp[255];

        if (de->d_name[0] == '.')
            continue;

        if ((!strcmp(de->d_name, "uevent")) ||
            (!strcmp(de->d_name, "subsystem")) ||
            (!strcmp(de->d_name, "device")) ||
            (!strcmp(de->d_name, "power"))) {
            continue;
        }

        sprintf(tmp, "%s/%s", sysfs_path, de->d_name);

        if (mmc_bootstrap_card(tmp) < 0)
            LOG_ERROR("Error bootstrapping card '%s' (%s)", tmp, strerror(errno));
    } // while

    closedir(d);
    return 0;   
}

static int mmc_bootstrap_card(char *sysfs_path)
{
    char saved_cwd[255];
    char new_cwd[255];
    char *devpath;
    char *uevent_params[4];
    char *p;
    char filename[255];
    char tmp[255];
    ssize_t sz;

#if DEBUG_BOOTSTRAP
    LOG_VOL("bootstrap_card(%s):", sysfs_path);
#endif

    /*
     * sysfs_path is based on /sys/class, but we want the actual device class
     */
    if (!getcwd(saved_cwd, sizeof(saved_cwd))) {
        LOGE("Error getting working dir path");
        return -errno;
    }
    
    if (chdir(sysfs_path) < 0) {
        LOGE("Unable to chdir to %s (%s)", sysfs_path, strerror(errno));
        return -errno;
    }

    if (!getcwd(new_cwd, sizeof(new_cwd))) {
        LOGE("Buffer too small for device path");
        return -errno;
    }

    if (chdir(saved_cwd) < 0) {
        LOGE("Unable to restore working dir");
        return -errno;
    }

    devpath = &new_cwd[4]; // Skip over '/sys'

    /*
     * Collect parameters so we can simulate a UEVENT
     */
    sprintf(tmp, "DEVPATH=%s", devpath);
    uevent_params[0] = (char *) strdup(tmp);

    sprintf(filename, "/sys%s/type", devpath);
    p = read_file(filename, &sz);
    p[strlen(p) - 1] = '\0';
    sprintf(tmp, "MMC_TYPE=%s", p);
    free(p);
    uevent_params[1] = (char *) strdup(tmp);

    sprintf(filename, "/sys%s/name", devpath);
    p = read_file(filename, &sz);
    p[strlen(p) - 1] = '\0';
    sprintf(tmp, "MMC_NAME=%s", p);
    free(p);
    uevent_params[2] = (char *) strdup(tmp);

    uevent_params[3] = (char *) NULL;

    if (simulate_uevent("mmc", devpath, "add", uevent_params) < 0) {
        LOGE("Error simulating uevent (%s)", strerror(errno));
        return -errno;
    }

    /*
     *  Check for block drivers
     */
    char block_devpath[255];
    sprintf(tmp, "%s/block", devpath);
    sprintf(filename, "/sys%s/block", devpath);
    if (!access(filename, F_OK)) {
        if (mmc_bootstrap_block(tmp)) {
            LOGE("Error bootstrapping block @ %s", tmp);
        }
    }

    return 0;
}

static int mmc_bootstrap_block(char *devpath)
{
    char blockdir_path[255];
    DIR *d;
    struct dirent *de;

#if DEBUG_BOOTSTRAP
    LOG_VOL("mmc_bootstrap_block(%s):", devpath);
#endif

    sprintf(blockdir_path, "/sys%s", devpath);

    if (!(d = opendir(blockdir_path))) {
        LOGE("Failed to opendir %s", devpath);
        return -errno;
    }

    while ((de = readdir(d))) {
        char tmp[255];

        if (de->d_name[0] == '.')
            continue;
        sprintf(tmp, "%s/%s", devpath, de->d_name);
        if (mmc_bootstrap_mmcblk(tmp))
            LOGE("Error bootstraping mmcblk @ %s", tmp);
    }
    closedir(d);
    return 0;
}

static int mmc_bootstrap_mmcblk(char *devpath)
{
    char *mmcblk_devname;
    int part_no;
    int rc;

#if DEBUG_BOOTSTRAP
    LOG_VOL("mmc_bootstrap_mmcblk(%s):", devpath);
#endif

    if ((rc = mmc_bootstrap_mmcblk_partition(devpath))) {
        LOGE("Error bootstrapping mmcblk partition '%s'", devpath);
        return rc;
    }

    for (mmcblk_devname = &devpath[strlen(devpath)];
         *mmcblk_devname != '/'; mmcblk_devname--);
    mmcblk_devname++;

    for (part_no = 1; part_no <= NDOSPART; part_no++) {
        char part_file[255];
        sprintf(part_file, "/sys%s/%sp%d", devpath, mmcblk_devname, part_no);
        if (!access(part_file, F_OK)) {
            char part_devpath[255];

            sprintf(part_devpath, "%s/%sp%d", devpath, mmcblk_devname, part_no);
            if (mmc_bootstrap_mmcblk_partition(part_devpath)) 
                LOGE("Error bootstrapping mmcblk partition '%s'", part_devpath);
        }
    }

    return 0;
}

static int mmc_bootstrap_mmcblk_partition(char *devpath)
{
    char filename[255];
    char *uevent_buffer;
    ssize_t sz;
    char *uevent_params[4];
    char tmp[255];
    FILE *fp;
    char line[255];

#if DEBUG_BOOTSTRAP
    LOG_VOL("mmc_bootstrap_mmcblk_partition(%s):", devpath);
#endif

    sprintf(tmp, "DEVPATH=%s", devpath);
    uevent_params[0] = strdup(tmp);

    sprintf(filename, "/sys%s/uevent", devpath);
    if (!(fp = fopen(filename, "r"))) {
        LOGE("Unable to open '%s' (%s)", filename, strerror(errno));
        return -errno;
    }

    while (fgets(line, sizeof(line), fp)) {
        line[strlen(line)-1] = 0;
        if (!strncmp(line, "DEVTYPE=", 8))
            uevent_params[1] = strdup(line);
        else if (!strncmp(line, "MAJOR=",6)) 
            uevent_params[2] = strdup(line);
        else if (!strncmp(line, "MINOR=",6)) 
            uevent_params[3] = strdup(line);
    }
    fclose(fp);

    if (!uevent_params[1] || !uevent_params[2] || !uevent_params[3]) {
        LOGE("mmcblk uevent missing required params");
        return -1;
    }
    uevent_params[4] = '\0';
    
    if (simulate_uevent("block", devpath, "add", uevent_params) < 0) {
        LOGE("Error simulating uevent (%s)", strerror(errno));
        return -errno;
    }
    return 0;
}

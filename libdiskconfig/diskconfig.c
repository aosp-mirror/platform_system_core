/* libs/diskconfig/diskconfig.c
 *
 * Copyright 2008, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "diskconfig"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include <linux/fs.h>

#include <cutils/config_utils.h>
#include <cutils/log.h>

#include <diskconfig/diskconfig.h>


static int
parse_len(const char *str, uint64_t *plen)
{
    char tmp[64];
    int len_str;
    uint32_t multiple = 1;

    strncpy(tmp, str, sizeof(tmp));
    tmp[sizeof(tmp)-1] = '\0';
    len_str = strlen(tmp);
    if (!len_str) {
        LOGE("Invalid disk length specified.");
        return 1;
    }

    switch(tmp[len_str - 1]) {
        case 'M': case 'm':
            /* megabyte */
            multiple <<= 10;
        case 'K': case 'k':
            /* kilobytes */
            multiple <<= 10;
            tmp[len_str - 1] = '\0';
            break;
        default:
            break;
    }

    *plen = strtoull(tmp, NULL, 0);
    if (!*plen) {
        LOGE("Invalid length specified: %s", str);
        return 1;
    }

    if (*plen == (uint64_t)-1) {
        if (multiple > 1) {
            LOGE("Size modifier illegal when len is -1");
            return 1;
        }
    } else {
        /* convert len to kilobytes */
        if (multiple > 1024)
            multiple >>= 10;
        *plen *= multiple;

        if (*plen > 0xffffffffULL) {
            LOGE("Length specified is too large!: %llu KB", *plen);
            return 1;
        }
    }

    return 0;
}


static int
load_partitions(cnode *root, struct disk_info *dinfo)
{
    cnode *partnode;

    dinfo->num_parts = 0;
    for (partnode = root->first_child; partnode; partnode = partnode->next) {
        struct part_info *pinfo = &dinfo->part_lst[dinfo->num_parts];
        const char *tmp;

        /* bleh, i will leak memory here, but i DONT CARE since
         * the only right thing to do when this function fails
         * is to quit */
        pinfo->name = strdup(partnode->name);

        if(config_bool(partnode, "active", 0))
            pinfo->flags |= PART_ACTIVE_FLAG;

        if (!(tmp = config_str(partnode, "type", NULL))) {
            LOGE("Partition type required: %s", pinfo->name);
            return 1;
        }

        /* possible values are: linux, fat32 */
        if (!strcmp(tmp, "linux")) {
            pinfo->type = PC_PART_TYPE_LINUX;
        } else if (!strcmp(tmp, "fat32")) {
            pinfo->type = PC_PART_TYPE_FAT32;
        } else {
            LOGE("Unsupported partition type found: %s", tmp);
            return 1;
        }

        if ((tmp = config_str(partnode, "len", NULL)) != NULL) {
            uint64_t len;
            if (parse_len(tmp, &len))
                return 1;
            pinfo->len_kb = (uint32_t) len;
        } else 
            pinfo->len_kb = 0;

        ++dinfo->num_parts;
    }

    return 0;
}

struct disk_info *
load_diskconfig(const char *fn, char *path_override)
{
    struct disk_info *dinfo;
    cnode *devroot;
    cnode *partnode;
    cnode *root = config_node("", "");
    const char *tmp;

    if (!(dinfo = malloc(sizeof(struct disk_info)))) {
        LOGE("Could not malloc disk_info");
        return NULL;
    }
    memset(dinfo, 0, sizeof(struct disk_info));

    if (!(dinfo->part_lst = malloc(MAX_NUM_PARTS * sizeof(struct part_info)))) {
        LOGE("Could not malloc part_lst");
        goto fail;
    }
    memset(dinfo->part_lst, 0,
           (MAX_NUM_PARTS * sizeof(struct part_info)));

    config_load_file(root, fn);
    if (root->first_child == NULL) {
        LOGE("Could not read config file %s", fn);
        goto fail;
    }

    if (!(devroot = config_find(root, "device"))) {
        LOGE("Could not find device section in config file '%s'", fn);
        goto fail;
    }


    if (!(tmp = config_str(devroot, "path", path_override))) {
        LOGE("device path is requried");
        goto fail;
    }
    dinfo->device = strdup(tmp);

    /* find the partition scheme */
    if (!(tmp = config_str(devroot, "scheme", NULL))) {
        LOGE("partition scheme is required");
        goto fail;
    } else if (!strcmp(tmp, "mbr")) {
        dinfo->scheme = PART_SCHEME_MBR;
    } else if (!strcmp(tmp, "gpt")) {
        LOGE("'gpt' partition scheme not supported yet.");
        goto fail;
    } else {
        LOGE("Unknown partition scheme specified: %s", tmp);
        goto fail;
    }

    /* grab the sector size (in bytes) */
    tmp = config_str(devroot, "sector_size", "512");
    dinfo->sect_size = strtol(tmp, NULL, 0);
    if (!dinfo->sect_size) {
        LOGE("Invalid sector size: %s", tmp);
        goto fail;
    }

    /* first lba where the partitions will start on disk */
    if (!(tmp = config_str(devroot, "start_lba", NULL))) {
        LOGE("start_lba must be provided");
        goto fail;
    }

    if (!(dinfo->skip_lba = strtol(tmp, NULL, 0))) {
        LOGE("Invalid starting LBA (or zero): %s", tmp);
        goto fail;
    }

    /* Number of LBAs on disk */
    if (!(tmp = config_str(devroot, "num_lba", NULL))) {
        LOGE("num_lba is required");
        goto fail;
    }
    dinfo->num_lba = strtoul(tmp, NULL, 0);

    if (!(partnode = config_find(devroot, "partitions"))) {
        LOGE("Device must specify partition list");
        goto fail;
    }

    if (load_partitions(partnode, dinfo))
        goto fail;

    return dinfo;

fail:
    if (dinfo->part_lst)
        free(dinfo->part_lst);
    if (dinfo->device)
        free(dinfo->device);
    free(dinfo);
    return NULL;
}

static int
sync_ptable(int fd)
{
    struct stat stat;
    int rv;

    sync();

    if (fstat(fd, &stat)) {
       LOGE("Cannot stat, errno=%d.", errno);
       return -1;
    }

    if (S_ISBLK(stat.st_mode) && ((rv = ioctl(fd, BLKRRPART, NULL)) < 0)) {
        LOGE("Could not re-read partition table. REBOOT!. (errno=%d)", errno);
        return -1;
    }

    return 0;
}

/* This function verifies that the disk info provided is valid, and if so,
 * returns an open file descriptor.
 *
 * This does not necessarily mean that it will later be successfully written
 * though. If we use the pc-bios partitioning scheme, we must use extended
 * partitions, which eat up some hd space. If the user manually provisioned
 * every single partition, but did not account for the extra needed space,
 * then we will later fail.
 *
 * TODO: Make validation more complete.
 */
static int
validate(struct disk_info *dinfo)
{
    int fd;
    int sect_sz;
    uint64_t disk_size;
    uint64_t total_size;
    int cnt;
    struct stat stat;

    if (!dinfo)
        return -1;

    if ((fd = open(dinfo->device, O_RDWR)) < 0) {
        LOGE("Cannot open device '%s' (errno=%d)", dinfo->device, errno);
        return -1;
    }

    if (fstat(fd, &stat)) {
        LOGE("Cannot stat file '%s', errno=%d.", dinfo->device, errno);
        goto fail;
    }


    /* XXX: Some of the code below is kind of redundant and should probably
     * be refactored a little, but it will do for now. */

    /* Verify that we can operate on the device that was requested.
     * We presently only support block devices and regular file images. */
    if (S_ISBLK(stat.st_mode)) {
        /* get the sector size and make sure we agree */
        if (ioctl(fd, BLKSSZGET, &sect_sz) < 0) {
            LOGE("Cannot get sector size (errno=%d)", errno);
            goto fail;
        }

        if (!sect_sz || sect_sz != dinfo->sect_size) {
            LOGE("Device sector size is zero or sector sizes do not match!");
            goto fail;
        }

        /* allow the user override the "disk size" if they provided num_lba */
        if (!dinfo->num_lba) {
            if (ioctl(fd, BLKGETSIZE64, &disk_size) < 0) {
                LOGE("Could not get block device size (errno=%d)", errno);
                goto fail;
            }
            /* XXX: we assume that the disk has < 2^32 sectors :-) */
            dinfo->num_lba = (uint32_t)(disk_size / (uint64_t)dinfo->sect_size);
        } else
            disk_size = (uint64_t)dinfo->num_lba * (uint64_t)dinfo->sect_size;
    } else if (S_ISREG(stat.st_mode)) {
        LOGI("Requesting operation on a regular file, not block device.");
        if (!dinfo->sect_size) {
            LOGE("Sector size for regular file images cannot be zero");
            goto fail;
        }
        if (dinfo->num_lba)
            disk_size = (uint64_t)dinfo->num_lba * (uint64_t)dinfo->sect_size;
        else {
            dinfo->num_lba = (uint32_t)(stat.st_size / dinfo->sect_size);
            disk_size = (uint64_t)stat.st_size;
        }
    } else {
        LOGE("Device does not refer to a regular file or a block device!");
        goto fail;
    }

#if 1
    LOGV("Device/file %s: size=%llu bytes, num_lba=%u, sect_size=%d",
         dinfo->device, disk_size, dinfo->num_lba, dinfo->sect_size);
#endif

    /* since this is our offset into the disk, we start off with that as
     * our size of needed partitions */
    total_size = dinfo->skip_lba * dinfo->sect_size;

    /* add up all the partition sizes and make sure it fits */
    for (cnt = 0; cnt < dinfo->num_parts; ++cnt) {
        struct part_info *part = &dinfo->part_lst[cnt];
        if (part->len_kb != (uint32_t)-1) {
            total_size += part->len_kb * 1024;
        } else if (part->len_kb == 0) {
            LOGE("Zero-size partition '%s' is invalid.", part->name);
            goto fail;
        } else {
            /* the partition requests the rest of the disk. */
            if (cnt + 1 != dinfo->num_parts) {
                LOGE("Only the last partition in the list can request to fill "
                     "the rest of disk.");
                goto fail;
            }
        }

        if ((part->type != PC_PART_TYPE_LINUX) &&
            (part->type != PC_PART_TYPE_FAT32)) {
            LOGE("Unknown partition type (0x%x) encountered for partition "
                 "'%s'\n", part->type, part->name);
            goto fail;
        }
    }

    /* only matters for disks, not files */
    if (S_ISBLK(stat.st_mode) && total_size > disk_size) {
        LOGE("Total requested size of partitions (%llu) is greater than disk "
             "size (%llu).", total_size, disk_size);
        goto fail;
    }

    return fd;

fail:
    close(fd);
    return -1;
}

static int
validate_and_config(struct disk_info *dinfo, int *fd, struct write_list **lst)
{
    *lst = NULL;
    *fd = -1;

    if ((*fd = validate(dinfo)) < 0)
        return 1;

    switch (dinfo->scheme) {
        case PART_SCHEME_MBR:
            *lst = config_mbr(dinfo);
            return *lst == NULL;
        case PART_SCHEME_GPT:
            /* not supported yet */
        default:
            LOGE("Uknown partition scheme.");
            break;
    }

    close(*fd);
    *lst = NULL;
    return 1;
}

/* validate and process the disk layout configuration.
 * This will cause an update to the partitions' start lba.
 *
 * Basically, this does the same thing as apply_disk_config in test mode,
 * except that wlist_commit is not called to print out the data to be
 * written.
 */
int
process_disk_config(struct disk_info *dinfo)
{
    struct write_list *lst;
    int fd;

    if (validate_and_config(dinfo, &fd, &lst) != 0)
        return 1;

    close(fd);
    wlist_free(lst);
    return 0;
}


int
apply_disk_config(struct disk_info *dinfo, int test)
{
    int fd;
    struct write_list *wr_lst = NULL;
    int rv;

    if (validate_and_config(dinfo, &fd, &wr_lst) != 0) {
        LOGE("Configuration is invalid.");
        goto fail;
    }

    if ((rv = wlist_commit(fd, wr_lst, test)) >= 0)
        rv = test ? 0 : sync_ptable(fd);

    close(fd);
    wlist_free(wr_lst);
    return rv;

fail:
    close(fd);
    if (wr_lst)
        wlist_free(wr_lst);
    return 1;
}

int
dump_disk_config(struct disk_info *dinfo)
{
    int cnt;
    struct part_info *part;

    printf("Device: %s\n", dinfo->device);
    printf("Scheme: ");
    switch (dinfo->scheme) {
        case PART_SCHEME_MBR:
            printf("MBR");
            break;
        case PART_SCHEME_GPT:
            printf("GPT (unsupported)");
            break;
        default:
            printf("Unknown");
            break;
    }
    printf ("\n");

    printf("Sector size: %d\n", dinfo->sect_size);
    printf("Skip leading LBAs: %u\n", dinfo->skip_lba);
    printf("Number of LBAs: %u\n", dinfo->num_lba);
    printf("Partitions:\n");

    for (cnt = 0; cnt < dinfo->num_parts; ++cnt) {
        part = &dinfo->part_lst[cnt];
        printf("\tname = %s\n", part->name);
        printf("\t\tflags = %s\n",
               part->flags & PART_ACTIVE_FLAG ? "Active" : "None");
        printf("\t\ttype = %s\n",
               part->type == PC_PART_TYPE_LINUX ? "Linux" : "Unknown");
        if (part->len_kb == (uint32_t)-1)
            printf("\t\tlen = rest of disk\n");
        else
            printf("\t\tlen = %uKB\n", part->len_kb);
    }
    printf("Total number of partitions: %d\n", cnt);
    printf("\n");

    return 0;
}

struct part_info *
find_part(struct disk_info *dinfo, const char *name)
{
    struct part_info *pinfo;
    int cnt;

    for (cnt = 0; cnt < dinfo->num_parts; ++cnt) {
        pinfo = &dinfo->part_lst[cnt];
        if (!strcmp(pinfo->name, name))
            return pinfo;
    }

    return NULL;
}

/* NOTE: If the returned ptr is non-NULL, it must be freed by the caller. */
char *
find_part_device(struct disk_info *dinfo, const char *name)
{
    switch (dinfo->scheme) {
        case PART_SCHEME_MBR:
            return find_mbr_part(dinfo, name);
        case PART_SCHEME_GPT:
            LOGE("GPT is presently not supported");
            break;
        default:
            LOGE("Unknown partition table scheme");
            break;
    }

    return NULL;
}



/*
 * Copyright (C) 2013 The Android Open Source Project
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

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <libgen.h>
#include <time.h>

#include <android-base/file.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <cutils/properties.h>
#include <logwrap/logwrap.h>

#include "mincrypt/rsa.h"
#include "mincrypt/sha.h"
#include "mincrypt/sha256.h"

#include "fec/io.h"

#include "fs_mgr.h"
#include "fs_mgr_priv.h"
#include "fs_mgr_priv_verity.h"

#define FSTAB_PREFIX "/fstab."

#define VERITY_TABLE_RSA_KEY "/verity_key"
#define VERITY_TABLE_HASH_IDX 8
#define VERITY_TABLE_SALT_IDX 9

#define VERITY_TABLE_OPT_RESTART "restart_on_corruption"
#define VERITY_TABLE_OPT_LOGGING "ignore_corruption"
#define VERITY_TABLE_OPT_IGNZERO "ignore_zero_blocks"

#define VERITY_TABLE_OPT_FEC_FORMAT \
    "use_fec_from_device %s fec_start %" PRIu64 " fec_blocks %" PRIu64 \
    " fec_roots %u " VERITY_TABLE_OPT_IGNZERO
#define VERITY_TABLE_OPT_FEC_ARGS 9

#define METADATA_MAGIC 0x01564c54
#define METADATA_TAG_MAX_LENGTH 63
#define METADATA_EOD "eod"

#define VERITY_LASTSIG_TAG "verity_lastsig"

#define VERITY_STATE_TAG "verity_state"
#define VERITY_STATE_HEADER 0x83c0ae9d
#define VERITY_STATE_VERSION 1

#define VERITY_KMSG_RESTART "dm-verity device corrupted"
#define VERITY_KMSG_BUFSIZE 1024

#define READ_BUF_SIZE 4096

#define __STRINGIFY(x) #x
#define STRINGIFY(x) __STRINGIFY(x)

struct verity_state {
    uint32_t header;
    uint32_t version;
    int32_t mode;
};

extern struct fs_info info;

static RSAPublicKey *load_key(const char *path)
{
    RSAPublicKey* key = static_cast<RSAPublicKey*>(malloc(sizeof(RSAPublicKey)));
    if (!key) {
        ERROR("Can't malloc key\n");
        return NULL;
    }

    FILE* f = fopen(path, "r");
    if (!f) {
        ERROR("Can't open '%s'\n", path);
        free(key);
        return NULL;
    }

    if (!fread(key, sizeof(*key), 1, f)) {
        ERROR("Could not read key!\n");
        fclose(f);
        free(key);
        return NULL;
    }

    if (key->len != RSANUMWORDS) {
        ERROR("Invalid key length %d\n", key->len);
        fclose(f);
        free(key);
        return NULL;
    }

    fclose(f);
    return key;
}

static int verify_table(const uint8_t *signature, const char *table,
        uint32_t table_length)
{
    RSAPublicKey *key;
    uint8_t hash_buf[SHA256_DIGEST_SIZE];
    int retval = -1;

    // Hash the table
    SHA256_hash((uint8_t*)table, table_length, hash_buf);

    // Now get the public key from the keyfile
    key = load_key(VERITY_TABLE_RSA_KEY);
    if (!key) {
        ERROR("Couldn't load verity keys\n");
        goto out;
    }

    // verify the result
    if (!RSA_verify(key,
                    signature,
                    RSANUMBYTES,
                    (uint8_t*) hash_buf,
                    SHA256_DIGEST_SIZE)) {
        ERROR("Couldn't verify table\n");
        goto out;
    }

    retval = 0;

out:
    free(key);
    return retval;
}

static int verify_verity_signature(const struct fec_verity_metadata& verity)
{
    if (verify_table(verity.signature, verity.table,
            verity.table_length) == 0 ||
        verify_table(verity.ecc_signature, verity.table,
            verity.table_length) == 0) {
        return 0;
    }

    return -1;
}

static int invalidate_table(char *table, size_t table_length)
{
    size_t n = 0;
    size_t idx = 0;
    size_t cleared = 0;

    while (n < table_length) {
        if (table[n++] == ' ') {
            ++idx;
        }

        if (idx != VERITY_TABLE_HASH_IDX && idx != VERITY_TABLE_SALT_IDX) {
            continue;
        }

        while (n < table_length && table[n] != ' ') {
            table[n++] = '0';
        }

        if (++cleared == 2) {
            return 0;
        }
    }

    return -1;
}

static void verity_ioctl_init(struct dm_ioctl *io, const char *name, unsigned flags)
{
    memset(io, 0, DM_BUF_SIZE);
    io->data_size = DM_BUF_SIZE;
    io->data_start = sizeof(struct dm_ioctl);
    io->version[0] = 4;
    io->version[1] = 0;
    io->version[2] = 0;
    io->flags = flags | DM_READONLY_FLAG;
    if (name) {
        strlcpy(io->name, name, sizeof(io->name));
    }
}

static int create_verity_device(struct dm_ioctl *io, char *name, int fd)
{
    verity_ioctl_init(io, name, 1);
    if (ioctl(fd, DM_DEV_CREATE, io)) {
        ERROR("Error creating device mapping (%s)", strerror(errno));
        return -1;
    }
    return 0;
}

static int destroy_verity_device(struct dm_ioctl *io, char *name, int fd)
{
    verity_ioctl_init(io, name, 0);
    if (ioctl(fd, DM_DEV_REMOVE, io)) {
        ERROR("Error removing device mapping (%s)", strerror(errno));
        return -1;
    }
    return 0;
}

static int get_verity_device_name(struct dm_ioctl *io, char *name, int fd, char **dev_name)
{
    verity_ioctl_init(io, name, 0);
    if (ioctl(fd, DM_DEV_STATUS, io)) {
        ERROR("Error fetching verity device number (%s)", strerror(errno));
        return -1;
    }
    int dev_num = (io->dev & 0xff) | ((io->dev >> 12) & 0xfff00);
    if (asprintf(dev_name, "/dev/block/dm-%u", dev_num) < 0) {
        ERROR("Error getting verity block device name (%s)", strerror(errno));
        return -1;
    }
    return 0;
}

struct verity_table_params {
    char *table;
    int mode;
    struct fec_ecc_metadata ecc;
    const char *ecc_dev;
};

typedef bool (*format_verity_table_func)(char *buf, const size_t bufsize,
        const struct verity_table_params *params);

static bool format_verity_table(char *buf, const size_t bufsize,
        const struct verity_table_params *params)
{
    const char *mode_flag = NULL;
    int res = -1;

    if (params->mode == VERITY_MODE_RESTART) {
        mode_flag = VERITY_TABLE_OPT_RESTART;
    } else if (params->mode == VERITY_MODE_LOGGING) {
        mode_flag = VERITY_TABLE_OPT_LOGGING;
    }

    if (params->ecc.valid) {
        if (mode_flag) {
            res = snprintf(buf, bufsize,
                    "%s %u %s " VERITY_TABLE_OPT_FEC_FORMAT,
                    params->table, 1 + VERITY_TABLE_OPT_FEC_ARGS, mode_flag, params->ecc_dev,
                    params->ecc.start / FEC_BLOCKSIZE, params->ecc.blocks, params->ecc.roots);
        } else {
            res = snprintf(buf, bufsize,
                    "%s %u " VERITY_TABLE_OPT_FEC_FORMAT,
                    params->table, VERITY_TABLE_OPT_FEC_ARGS, params->ecc_dev,
                    params->ecc.start / FEC_BLOCKSIZE, params->ecc.blocks, params->ecc.roots);
        }
    } else if (mode_flag) {
        res = snprintf(buf, bufsize, "%s 2 " VERITY_TABLE_OPT_IGNZERO " %s", params->table,
                    mode_flag);
    } else {
        res = snprintf(buf, bufsize, "%s 1 " VERITY_TABLE_OPT_IGNZERO, params->table);
    }

    if (res < 0 || (size_t)res >= bufsize) {
        ERROR("Error building verity table; insufficient buffer size?\n");
        return false;
    }

    return true;
}

static bool format_legacy_verity_table(char *buf, const size_t bufsize,
        const struct verity_table_params *params)
{
    int res;

    if (params->mode == VERITY_MODE_EIO) {
        res = strlcpy(buf, params->table, bufsize);
    } else {
        res = snprintf(buf, bufsize, "%s %d", params->table, params->mode);
    }

    if (res < 0 || (size_t)res >= bufsize) {
        ERROR("Error building verity table; insufficient buffer size?\n");
        return false;
    }

    return true;
}

static int load_verity_table(struct dm_ioctl *io, char *name, uint64_t device_size, int fd,
        const struct verity_table_params *params, format_verity_table_func format)
{
    char *verity_params;
    char *buffer = (char*) io;
    size_t bufsize;

    verity_ioctl_init(io, name, DM_STATUS_TABLE_FLAG);

    struct dm_target_spec *tgt = (struct dm_target_spec *) &buffer[sizeof(struct dm_ioctl)];

    // set tgt arguments
    io->target_count = 1;
    tgt->status = 0;
    tgt->sector_start = 0;
    tgt->length = device_size / 512;
    strcpy(tgt->target_type, "verity");

    // build the verity params
    verity_params = buffer + sizeof(struct dm_ioctl) + sizeof(struct dm_target_spec);
    bufsize = DM_BUF_SIZE - (verity_params - buffer);

    if (!format(verity_params, bufsize, params)) {
        ERROR("Failed to format verity parameters\n");
        return -1;
    }

    INFO("loading verity table: '%s'", verity_params);

    // set next target boundary
    verity_params += strlen(verity_params) + 1;
    verity_params = (char*)(((unsigned long)verity_params + 7) & ~8);
    tgt->next = verity_params - buffer;

    // send the ioctl to load the verity table
    if (ioctl(fd, DM_TABLE_LOAD, io)) {
        ERROR("Error loading verity table (%s)\n", strerror(errno));
        return -1;
    }

    return 0;
}

static int resume_verity_table(struct dm_ioctl *io, char *name, int fd)
{
    verity_ioctl_init(io, name, 0);
    if (ioctl(fd, DM_DEV_SUSPEND, io)) {
        ERROR("Error activating verity device (%s)", strerror(errno));
        return -1;
    }
    return 0;
}

static int test_access(char *device) {
    int tries = 25;
    while (tries--) {
        if (!access(device, F_OK) || errno != ENOENT) {
            return 0;
        }
        usleep(40 * 1000);
    }
    return -1;
}

static int check_verity_restart(const char *fname)
{
    char buffer[VERITY_KMSG_BUFSIZE + 1];
    int fd;
    int rc = 0;
    ssize_t size;
    struct stat s;

    fd = TEMP_FAILURE_RETRY(open(fname, O_RDONLY | O_CLOEXEC));

    if (fd == -1) {
        if (errno != ENOENT) {
            ERROR("Failed to open %s (%s)\n", fname, strerror(errno));
        }
        goto out;
    }

    if (fstat(fd, &s) == -1) {
        ERROR("Failed to fstat %s (%s)\n", fname, strerror(errno));
        goto out;
    }

    size = VERITY_KMSG_BUFSIZE;

    if (size > s.st_size) {
        size = s.st_size;
    }

    if (lseek(fd, s.st_size - size, SEEK_SET) == -1) {
        ERROR("Failed to lseek %jd %s (%s)\n", (intmax_t)(s.st_size - size), fname,
            strerror(errno));
        goto out;
    }

    if (!android::base::ReadFully(fd, buffer, size)) {
        ERROR("Failed to read %zd bytes from %s (%s)\n", size, fname,
            strerror(errno));
        goto out;
    }

    buffer[size] = '\0';

    if (strstr(buffer, VERITY_KMSG_RESTART) != NULL) {
        rc = 1;
    }

out:
    if (fd != -1) {
        close(fd);
    }

    return rc;
}

static int was_verity_restart()
{
    static const char *files[] = {
        "/sys/fs/pstore/console-ramoops",
        "/proc/last_kmsg",
        NULL
    };
    int i;

    for (i = 0; files[i]; ++i) {
        if (check_verity_restart(files[i])) {
            return 1;
        }
    }

    return 0;
}

static int metadata_add(FILE *fp, long start, const char *tag,
        unsigned int length, off64_t *offset)
{
    if (fseek(fp, start, SEEK_SET) < 0 ||
        fprintf(fp, "%s %u\n", tag, length) < 0) {
        return -1;
    }

    *offset = ftell(fp);

    if (fseek(fp, length, SEEK_CUR) < 0 ||
        fprintf(fp, METADATA_EOD " 0\n") < 0) {
        return -1;
    }

    return 0;
}

static int metadata_find(const char *fname, const char *stag,
        unsigned int slength, off64_t *offset)
{
    FILE *fp = NULL;
    char tag[METADATA_TAG_MAX_LENGTH + 1];
    int rc = -1;
    int n;
    long start = 0x4000; /* skip cryptfs metadata area */
    uint32_t magic;
    unsigned int length = 0;

    if (!fname) {
        return -1;
    }

    fp = fopen(fname, "r+");

    if (!fp) {
        ERROR("Failed to open %s (%s)\n", fname, strerror(errno));
        goto out;
    }

    /* check magic */
    if (fseek(fp, start, SEEK_SET) < 0 ||
        fread(&magic, sizeof(magic), 1, fp) != 1) {
        ERROR("Failed to read magic from %s (%s)\n", fname, strerror(errno));
        goto out;
    }

    if (magic != METADATA_MAGIC) {
        magic = METADATA_MAGIC;

        if (fseek(fp, start, SEEK_SET) < 0 ||
            fwrite(&magic, sizeof(magic), 1, fp) != 1) {
            ERROR("Failed to write magic to %s (%s)\n", fname, strerror(errno));
            goto out;
        }

        rc = metadata_add(fp, start + sizeof(magic), stag, slength, offset);
        if (rc < 0) {
            ERROR("Failed to add metadata to %s: %s\n", fname, strerror(errno));
        }

        goto out;
    }

    start += sizeof(magic);

    while (1) {
        n = fscanf(fp, "%" STRINGIFY(METADATA_TAG_MAX_LENGTH) "s %u\n",
                tag, &length);

        if (n == 2 && strcmp(tag, METADATA_EOD)) {
            /* found a tag */
            start = ftell(fp);

            if (!strcmp(tag, stag) && length == slength) {
                *offset = start;
                rc = 0;
                goto out;
            }

            start += length;

            if (fseek(fp, length, SEEK_CUR) < 0) {
                ERROR("Failed to seek %s (%s)\n", fname, strerror(errno));
                goto out;
            }
        } else {
            rc = metadata_add(fp, start, stag, slength, offset);
            if (rc < 0) {
                ERROR("Failed to write metadata to %s: %s\n", fname,
                    strerror(errno));
            }
            goto out;
        }
   }

out:
    if (fp) {
        fflush(fp);
        fclose(fp);
    }

    return rc;
}

static int write_verity_state(const char *fname, off64_t offset, int32_t mode)
{
    int fd;
    int rc = -1;
    struct verity_state s = { VERITY_STATE_HEADER, VERITY_STATE_VERSION, mode };

    fd = TEMP_FAILURE_RETRY(open(fname, O_WRONLY | O_SYNC | O_CLOEXEC));

    if (fd == -1) {
        ERROR("Failed to open %s (%s)\n", fname, strerror(errno));
        goto out;
    }

    if (TEMP_FAILURE_RETRY(pwrite64(fd, &s, sizeof(s), offset)) != sizeof(s)) {
        ERROR("Failed to write %zu bytes to %s to offset %" PRIu64 " (%s)\n",
            sizeof(s), fname, offset, strerror(errno));
        goto out;
    }

    rc = 0;

out:
    if (fd != -1) {
        close(fd);
    }

    return rc;
}

static int read_verity_state(const char *fname, off64_t offset, int *mode)
{
    int fd = -1;
    int rc = -1;
    struct verity_state s;

    fd = TEMP_FAILURE_RETRY(open(fname, O_RDONLY | O_CLOEXEC));

    if (fd == -1) {
        ERROR("Failed to open %s (%s)\n", fname, strerror(errno));
        goto out;
    }

    if (TEMP_FAILURE_RETRY(pread64(fd, &s, sizeof(s), offset)) != sizeof(s)) {
        ERROR("Failed to read %zu bytes from %s offset %" PRIu64 " (%s)\n",
            sizeof(s), fname, offset, strerror(errno));
        goto out;
    }

    if (s.header != VERITY_STATE_HEADER) {
        /* space allocated, but no state written. write default state */
        *mode = VERITY_MODE_DEFAULT;
        rc = write_verity_state(fname, offset, *mode);
        goto out;
    }

    if (s.version != VERITY_STATE_VERSION) {
        ERROR("Unsupported verity state version (%u)\n", s.version);
        goto out;
    }

    if (s.mode < VERITY_MODE_EIO ||
        s.mode > VERITY_MODE_LAST) {
        ERROR("Unsupported verity mode (%u)\n", s.mode);
        goto out;
    }

    *mode = s.mode;
    rc = 0;

out:
    if (fd != -1) {
        close(fd);
    }

    return rc;
}

static int read_partition(const char *path, uint64_t size)
{
    char buf[READ_BUF_SIZE];
    ssize_t size_read;
    android::base::unique_fd fd(TEMP_FAILURE_RETRY(open(path, O_RDONLY | O_CLOEXEC)));

    if (fd == -1) {
        ERROR("Failed to open %s: %s\n", path, strerror(errno));
        return -errno;
    }

    while (size) {
        size_read = TEMP_FAILURE_RETRY(read(fd, buf, READ_BUF_SIZE));
        if (size_read == -1) {
            ERROR("Error in reading partition %s: %s\n", path,
                  strerror(errno));
            return -errno;
        }
        size -= size_read;
    }

    return 0;
}

static int compare_last_signature(struct fstab_rec *fstab, int *match)
{
    char tag[METADATA_TAG_MAX_LENGTH + 1];
    int fd = -1;
    int rc = -1;
    off64_t offset = 0;
    struct fec_handle *f = NULL;
    struct fec_verity_metadata verity;
    uint8_t curr[SHA256_DIGEST_SIZE];
    uint8_t prev[SHA256_DIGEST_SIZE];

    *match = 1;

    if (fec_open(&f, fstab->blk_device, O_RDONLY, FEC_VERITY_DISABLE,
            FEC_DEFAULT_ROOTS) == -1) {
        ERROR("Failed to open '%s' (%s)\n", fstab->blk_device,
            strerror(errno));
        return rc;
    }

    // read verity metadata
    if (fec_verity_get_metadata(f, &verity) == -1) {
        ERROR("Failed to get verity metadata '%s' (%s)\n", fstab->blk_device,
            strerror(errno));
        goto out;
    }

    SHA256_hash(verity.signature, RSANUMBYTES, curr);

    if (snprintf(tag, sizeof(tag), VERITY_LASTSIG_TAG "_%s",
            basename(fstab->mount_point)) >= (int)sizeof(tag)) {
        ERROR("Metadata tag name too long for %s\n", fstab->mount_point);
        goto out;
    }

    if (metadata_find(fstab->verity_loc, tag, SHA256_DIGEST_SIZE,
            &offset) < 0) {
        goto out;
    }

    fd = TEMP_FAILURE_RETRY(open(fstab->verity_loc, O_RDWR | O_SYNC | O_CLOEXEC));

    if (fd == -1) {
        ERROR("Failed to open %s: %s\n", fstab->verity_loc, strerror(errno));
        goto out;
    }

    if (TEMP_FAILURE_RETRY(pread64(fd, prev, sizeof(prev),
            offset)) != sizeof(prev)) {
        ERROR("Failed to read %zu bytes from %s offset %" PRIu64 " (%s)\n",
            sizeof(prev), fstab->verity_loc, offset, strerror(errno));
        goto out;
    }

    *match = !memcmp(curr, prev, SHA256_DIGEST_SIZE);

    if (!*match) {
        /* update current signature hash */
        if (TEMP_FAILURE_RETRY(pwrite64(fd, curr, sizeof(curr),
                offset)) != sizeof(curr)) {
            ERROR("Failed to write %zu bytes to %s offset %" PRIu64 " (%s)\n",
                sizeof(curr), fstab->verity_loc, offset, strerror(errno));
            goto out;
        }
    }

    rc = 0;

out:
    fec_close(f);
    return rc;
}

static int get_verity_state_offset(struct fstab_rec *fstab, off64_t *offset)
{
    char tag[METADATA_TAG_MAX_LENGTH + 1];

    if (snprintf(tag, sizeof(tag), VERITY_STATE_TAG "_%s",
            basename(fstab->mount_point)) >= (int)sizeof(tag)) {
        ERROR("Metadata tag name too long for %s\n", fstab->mount_point);
        return -1;
    }

    return metadata_find(fstab->verity_loc, tag, sizeof(struct verity_state),
                offset);
}

static int load_verity_state(struct fstab_rec *fstab, int *mode)
{
    char propbuf[PROPERTY_VALUE_MAX];
    int match = 0;
    off64_t offset = 0;

    /* unless otherwise specified, use EIO mode */
    *mode = VERITY_MODE_EIO;

    /* use the kernel parameter if set */
    property_get("ro.boot.veritymode", propbuf, "");

    if (*propbuf != '\0') {
        if (!strcmp(propbuf, "enforcing")) {
            *mode = VERITY_MODE_DEFAULT;
        }
        return 0;
    }

    if (get_verity_state_offset(fstab, &offset) < 0) {
        /* fall back to stateless behavior */
        return 0;
    }

    if (was_verity_restart()) {
        /* device was restarted after dm-verity detected a corrupted
         * block, so use EIO mode */
        return write_verity_state(fstab->verity_loc, offset, *mode);
    }

    if (!compare_last_signature(fstab, &match) && !match) {
        /* partition has been reflashed, reset dm-verity state */
        *mode = VERITY_MODE_DEFAULT;
        return write_verity_state(fstab->verity_loc, offset, *mode);
    }

    return read_verity_state(fstab->verity_loc, offset, mode);
}

int fs_mgr_load_verity_state(int *mode)
{
    char fstab_filename[PROPERTY_VALUE_MAX + sizeof(FSTAB_PREFIX)];
    char propbuf[PROPERTY_VALUE_MAX];
    int rc = -1;
    int i;
    int current;
    struct fstab *fstab = NULL;

    /* return the default mode, unless any of the verified partitions are in
     * logging mode, in which case return that */
    *mode = VERITY_MODE_DEFAULT;

    property_get("ro.hardware", propbuf, "");
    snprintf(fstab_filename, sizeof(fstab_filename), FSTAB_PREFIX"%s", propbuf);

    fstab = fs_mgr_read_fstab(fstab_filename);

    if (!fstab) {
        ERROR("Failed to read %s\n", fstab_filename);
        goto out;
    }

    for (i = 0; i < fstab->num_entries; i++) {
        if (!fs_mgr_is_verified(&fstab->recs[i])) {
            continue;
        }

        rc = load_verity_state(&fstab->recs[i], &current);
        if (rc < 0) {
            continue;
        }

        if (current != VERITY_MODE_DEFAULT) {
            *mode = current;
            break;
        }
    }

    rc = 0;

out:
    if (fstab) {
        fs_mgr_free_fstab(fstab);
    }

    return rc;
}

int fs_mgr_update_verity_state(fs_mgr_verity_state_callback callback)
{
    alignas(dm_ioctl) char buffer[DM_BUF_SIZE];
    bool system_root = false;
    char fstab_filename[PROPERTY_VALUE_MAX + sizeof(FSTAB_PREFIX)];
    const char *mount_point;
    char propbuf[PROPERTY_VALUE_MAX];
    char *status;
    int fd = -1;
    int i;
    int mode;
    int rc = -1;
    struct dm_ioctl *io = (struct dm_ioctl *) buffer;
    struct fstab *fstab = NULL;

    if (!callback) {
        return -1;
    }

    if (fs_mgr_load_verity_state(&mode) == -1) {
        return -1;
    }

    fd = TEMP_FAILURE_RETRY(open("/dev/device-mapper", O_RDWR | O_CLOEXEC));

    if (fd == -1) {
        ERROR("Error opening device mapper (%s)\n", strerror(errno));
        goto out;
    }

    property_get("ro.hardware", propbuf, "");
    snprintf(fstab_filename, sizeof(fstab_filename), FSTAB_PREFIX"%s", propbuf);

    property_get("ro.build.system_root_image", propbuf, "");
    system_root = !strcmp(propbuf, "true");

    fstab = fs_mgr_read_fstab(fstab_filename);

    if (!fstab) {
        ERROR("Failed to read %s\n", fstab_filename);
        goto out;
    }

    for (i = 0; i < fstab->num_entries; i++) {
        if (!fs_mgr_is_verified(&fstab->recs[i])) {
            continue;
        }

        if (system_root && !strcmp(fstab->recs[i].mount_point, "/")) {
            mount_point = "system";
        } else {
            mount_point = basename(fstab->recs[i].mount_point);
        }

        verity_ioctl_init(io, mount_point, 0);

        if (ioctl(fd, DM_TABLE_STATUS, io)) {
            ERROR("Failed to query DM_TABLE_STATUS for %s (%s)\n", mount_point,
                strerror(errno));
            continue;
        }

        status = &buffer[io->data_start + sizeof(struct dm_target_spec)];

        if (*status == 'C' || *status == 'V') {
            callback(&fstab->recs[i], mount_point, mode, *status);
        }
    }

    rc = 0;

out:
    if (fstab) {
        fs_mgr_free_fstab(fstab);
    }

    if (fd) {
        close(fd);
    }

    return rc;
}

static void update_verity_table_blk_device(char *blk_device, char **table)
{
    std::string result, word;
    auto tokens = android::base::Split(*table, " ");

    for (const auto token : tokens) {
        if (android::base::StartsWith(token, "/dev/block/") &&
            android::base::StartsWith(blk_device, token.c_str())) {
            word = blk_device;
        } else {
            word = token;
        }

        if (result.empty()) {
            result = word;
        } else {
            result += " " + word;
        }
    }

    if (result.empty()) {
        return;
    }

    free(*table);
    *table = strdup(result.c_str());
}

int fs_mgr_setup_verity(struct fstab_rec *fstab)
{
    int retval = FS_MGR_SETUP_VERITY_FAIL;
    int fd = -1;
    char *verity_blk_name = NULL;
    struct fec_handle *f = NULL;
    struct fec_verity_metadata verity;
    struct verity_table_params params = { .table = NULL };
    bool verified_at_boot = false;

    alignas(dm_ioctl) char buffer[DM_BUF_SIZE];
    struct dm_ioctl *io = (struct dm_ioctl *) buffer;
    char *mount_point = basename(fstab->mount_point);

    if (fec_open(&f, fstab->blk_device, O_RDONLY, FEC_VERITY_DISABLE,
            FEC_DEFAULT_ROOTS) < 0) {
        ERROR("Failed to open '%s' (%s)\n", fstab->blk_device,
            strerror(errno));
        return retval;
    }

    // read verity metadata
    if (fec_verity_get_metadata(f, &verity) < 0) {
        ERROR("Failed to get verity metadata '%s' (%s)\n", fstab->blk_device,
            strerror(errno));
        goto out;
    }

#ifdef ALLOW_ADBD_DISABLE_VERITY
    if (verity.disabled) {
        retval = FS_MGR_SETUP_VERITY_DISABLED;
        INFO("Attempt to cleanly disable verity - only works in USERDEBUG\n");
        goto out;
    }
#endif

    // read ecc metadata
    if (fec_ecc_get_metadata(f, &params.ecc) < 0) {
        params.ecc.valid = false;
    }

    params.ecc_dev = fstab->blk_device;

    // get the device mapper fd
    if ((fd = open("/dev/device-mapper", O_RDWR)) < 0) {
        ERROR("Error opening device mapper (%s)\n", strerror(errno));
        goto out;
    }

    // create the device
    if (create_verity_device(io, mount_point, fd) < 0) {
        ERROR("Couldn't create verity device!\n");
        goto out;
    }

    // get the name of the device file
    if (get_verity_device_name(io, mount_point, fd, &verity_blk_name) < 0) {
        ERROR("Couldn't get verity device number!\n");
        goto out;
    }

    if (load_verity_state(fstab, &params.mode) < 0) {
        /* if accessing or updating the state failed, switch to the default
         * safe mode. This makes sure the device won't end up in an endless
         * restart loop, and no corrupted data will be exposed to userspace
         * without a warning. */
        params.mode = VERITY_MODE_EIO;
    }

    if (!verity.table) {
        goto out;
    }

    params.table = strdup(verity.table);
    if (!params.table) {
        goto out;
    }

    // verify the signature on the table
    if (verify_verity_signature(verity) < 0) {
        if (params.mode == VERITY_MODE_LOGGING) {
            // the user has been warned, allow mounting without dm-verity
            retval = FS_MGR_SETUP_VERITY_SUCCESS;
            goto out;
        }

        // invalidate root hash and salt to trigger device-specific recovery
        if (invalidate_table(params.table, verity.table_length) < 0) {
            goto out;
        }
    }

    INFO("Enabling dm-verity for %s (mode %d)\n", mount_point, params.mode);

    if (fstab->fs_mgr_flags & MF_SLOTSELECT) {
        // Update the verity params using the actual block device path
        update_verity_table_blk_device(fstab->blk_device, &params.table);
    }

    // load the verity mapping table
    if (load_verity_table(io, mount_point, verity.data_size, fd, &params,
            format_verity_table) == 0) {
        goto loaded;
    }

    if (params.ecc.valid) {
        // kernel may not support error correction, try without
        INFO("Disabling error correction for %s\n", mount_point);
        params.ecc.valid = false;

        if (load_verity_table(io, mount_point, verity.data_size, fd, &params,
                format_verity_table) == 0) {
            goto loaded;
        }
    }

    // try the legacy format for backwards compatibility
    if (load_verity_table(io, mount_point, verity.data_size, fd, &params,
            format_legacy_verity_table) == 0) {
        goto loaded;
    }

    if (params.mode != VERITY_MODE_EIO) {
        // as a last resort, EIO mode should always be supported
        INFO("Falling back to EIO mode for %s\n", mount_point);
        params.mode = VERITY_MODE_EIO;

        if (load_verity_table(io, mount_point, verity.data_size, fd, &params,
                format_legacy_verity_table) == 0) {
            goto loaded;
        }
    }

    ERROR("Failed to load verity table for %s\n", mount_point);
    goto out;

loaded:

    // activate the device
    if (resume_verity_table(io, mount_point, fd) < 0) {
        goto out;
    }

    // mark the underlying block device as read-only
    fs_mgr_set_blk_ro(fstab->blk_device);

    // Verify the entire partition in one go
    // If there is an error, allow it to mount as a normal verity partition.
    if (fstab->fs_mgr_flags & MF_VERIFYATBOOT) {
        INFO("Verifying partition %s at boot\n", fstab->blk_device);
        int err = read_partition(verity_blk_name, verity.data_size);
        if (!err) {
            INFO("Verified verity partition %s at boot\n", fstab->blk_device);
            verified_at_boot = true;
        }
    }

    // assign the new verity block device as the block device
    if (!verified_at_boot) {
        free(fstab->blk_device);
        fstab->blk_device = verity_blk_name;
        verity_blk_name = 0;
    } else if (destroy_verity_device(io, mount_point, fd) < 0) {
        ERROR("Failed to remove verity device %s\n", mount_point);
        goto out;
    }

    // make sure we've set everything up properly
    if (test_access(fstab->blk_device) < 0) {
        goto out;
    }

    retval = FS_MGR_SETUP_VERITY_SUCCESS;

out:
    if (fd != -1) {
        close(fd);
    }

    fec_close(f);
    free(params.table);
    free(verity_blk_name);

    return retval;
}

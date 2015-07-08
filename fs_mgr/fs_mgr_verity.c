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

#include <private/android_filesystem_config.h>
#include <cutils/properties.h>
#include <logwrap/logwrap.h>

#include "mincrypt/rsa.h"
#include "mincrypt/sha.h"
#include "mincrypt/sha256.h"

#include "ext4_sb.h"
#include "squashfs_utils.h"

#include "fs_mgr_priv.h"
#include "fs_mgr_priv_verity.h"

#define FSTAB_PREFIX "/fstab."

#define VERITY_METADATA_SIZE 32768
#define VERITY_TABLE_RSA_KEY "/verity_key"

#define METADATA_MAGIC 0x01564c54
#define METADATA_TAG_MAX_LENGTH 63
#define METADATA_EOD "eod"

#define VERITY_LASTSIG_TAG "verity_lastsig"

#define VERITY_STATE_TAG "verity_state"
#define VERITY_STATE_HEADER 0x83c0ae9d
#define VERITY_STATE_VERSION 1

#define VERITY_KMSG_RESTART "dm-verity device corrupted"
#define VERITY_KMSG_BUFSIZE 1024

#define __STRINGIFY(x) #x
#define STRINGIFY(x) __STRINGIFY(x)

struct verity_state {
    uint32_t header;
    uint32_t version;
    int32_t mode;
};

extern struct fs_info info;

static RSAPublicKey *load_key(char *path)
{
    FILE *f;
    RSAPublicKey *key;

    key = malloc(sizeof(RSAPublicKey));
    if (!key) {
        ERROR("Can't malloc key\n");
        return NULL;
    }

    f = fopen(path, "r");
    if (!f) {
        ERROR("Can't open '%s'\n", path);
        free(key);
        return NULL;
    }

    if (!fread(key, sizeof(*key), 1, f)) {
        ERROR("Could not read key!");
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

static int verify_table(char *signature, char *table, int table_length)
{
    RSAPublicKey *key;
    uint8_t hash_buf[SHA256_DIGEST_SIZE];
    int retval = -1;

    // Hash the table
    SHA256_hash((uint8_t*)table, table_length, hash_buf);

    // Now get the public key from the keyfile
    key = load_key(VERITY_TABLE_RSA_KEY);
    if (!key) {
        ERROR("Couldn't load verity keys");
        goto out;
    }

    // verify the result
    if (!RSA_verify(key,
                    (uint8_t*) signature,
                    RSANUMBYTES,
                    (uint8_t*) hash_buf,
                    SHA256_DIGEST_SIZE)) {
        ERROR("Couldn't verify table.");
        goto out;
    }

    retval = 0;

out:
    free(key);
    return retval;
}

static int squashfs_get_target_device_size(char *blk_device, uint64_t *device_size)
{
    struct squashfs_info sq_info;

    if (squashfs_parse_sb(blk_device, &sq_info) >= 0) {
        *device_size = sq_info.bytes_used_4K_padded;
        return 0;
    } else {
        return -1;
    }
}

static int ext4_get_target_device_size(char *blk_device, uint64_t *device_size)
{
    int data_device;
    struct ext4_super_block sb;
    struct fs_info info;

    info.len = 0;  /* Only len is set to 0 to ask the device for real size. */

    data_device = TEMP_FAILURE_RETRY(open(blk_device, O_RDONLY | O_CLOEXEC));
    if (data_device == -1) {
        ERROR("Error opening block device (%s)", strerror(errno));
        return -1;
    }

    if (TEMP_FAILURE_RETRY(lseek64(data_device, 1024, SEEK_SET)) < 0) {
        ERROR("Error seeking to superblock");
        close(data_device);
        return -1;
    }

    if (TEMP_FAILURE_RETRY(read(data_device, &sb, sizeof(sb))) != sizeof(sb)) {
        ERROR("Error reading superblock");
        close(data_device);
        return -1;
    }

    ext4_parse_sb(&sb, &info);
    *device_size = info.len;

    close(data_device);
    return 0;
}

static int get_fs_size(char *fs_type, char *blk_device, uint64_t *device_size) {
    if (!strcmp(fs_type, "ext4")) {
        if (ext4_get_target_device_size(blk_device, device_size) < 0) {
            ERROR("Failed to get ext4 fs size on %s.", blk_device);
            return -1;
        }
    } else if (!strcmp(fs_type, "squashfs")) {
        if (squashfs_get_target_device_size(blk_device, device_size) < 0) {
            ERROR("Failed to get squashfs fs size on %s.", blk_device);
            return -1;
        }
    } else {
        ERROR("%s: Unsupported filesystem for verity.", fs_type);
        return -1;
    }
    return 0;
}

static int read_verity_metadata(uint64_t device_size, char *block_device, char **signature,
        char **table)
{
    unsigned magic_number;
    unsigned table_length;
    int protocol_version;
    int device;
    int retval = FS_MGR_SETUP_VERITY_FAIL;

    *signature = NULL;

    if (table) {
        *table = NULL;
    }

    device = TEMP_FAILURE_RETRY(open(block_device, O_RDONLY | O_CLOEXEC));
    if (device == -1) {
        ERROR("Could not open block device %s (%s).\n", block_device, strerror(errno));
        goto out;
    }

    if (TEMP_FAILURE_RETRY(lseek64(device, device_size, SEEK_SET)) < 0) {
        ERROR("Could not seek to start of verity metadata block.\n");
        goto out;
    }

    // check the magic number
    if (TEMP_FAILURE_RETRY(read(device, &magic_number, sizeof(magic_number))) !=
            sizeof(magic_number)) {
        ERROR("Couldn't read magic number!\n");
        goto out;
    }

#ifdef ALLOW_ADBD_DISABLE_VERITY
    if (magic_number == VERITY_METADATA_MAGIC_DISABLE) {
        retval = FS_MGR_SETUP_VERITY_DISABLED;
        INFO("Attempt to cleanly disable verity - only works in USERDEBUG");
        goto out;
    }
#endif

    if (magic_number != VERITY_METADATA_MAGIC_NUMBER) {
        ERROR("Couldn't find verity metadata at offset %"PRIu64"!\n", device_size);
        goto out;
    }

    // check the protocol version
    if (TEMP_FAILURE_RETRY(read(device, &protocol_version,
            sizeof(protocol_version))) != sizeof(protocol_version)) {
        ERROR("Couldn't read verity metadata protocol version!\n");
        goto out;
    }
    if (protocol_version != 0) {
        ERROR("Got unknown verity metadata protocol version %d!\n", protocol_version);
        goto out;
    }

    // get the signature
    *signature = (char*) malloc(RSANUMBYTES);
    if (!*signature) {
        ERROR("Couldn't allocate memory for signature!\n");
        goto out;
    }
    if (TEMP_FAILURE_RETRY(read(device, *signature, RSANUMBYTES)) != RSANUMBYTES) {
        ERROR("Couldn't read signature from verity metadata!\n");
        goto out;
    }

    if (!table) {
        retval = FS_MGR_SETUP_VERITY_SUCCESS;
        goto out;
    }

    // get the size of the table
    if (TEMP_FAILURE_RETRY(read(device, &table_length, sizeof(table_length))) !=
            sizeof(table_length)) {
        ERROR("Couldn't get the size of the verity table from metadata!\n");
        goto out;
    }

    // get the table + null terminator
    *table = malloc(table_length + 1);
    if (!*table) {
        ERROR("Couldn't allocate memory for verity table!\n");
        goto out;
    }
    if (TEMP_FAILURE_RETRY(read(device, *table, table_length)) !=
            (ssize_t)table_length) {
        ERROR("Couldn't read the verity table from metadata!\n");
        goto out;
    }

    (*table)[table_length] = 0;
    retval = FS_MGR_SETUP_VERITY_SUCCESS;

out:
    if (device != -1)
        close(device);

    if (retval != FS_MGR_SETUP_VERITY_SUCCESS) {
        free(*signature);
        *signature = NULL;

        if (table) {
            free(*table);
            *table = NULL;
        }
    }

    return retval;
}

static void verity_ioctl_init(struct dm_ioctl *io, char *name, unsigned flags)
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

static int load_verity_table(struct dm_ioctl *io, char *name, uint64_t device_size, int fd, char *table,
        int mode)
{
    char *verity_params;
    char *buffer = (char*) io;
    size_t bufsize;

    verity_ioctl_init(io, name, DM_STATUS_TABLE_FLAG);

    struct dm_target_spec *tgt = (struct dm_target_spec *) &buffer[sizeof(struct dm_ioctl)];

    // set tgt arguments here
    io->target_count = 1;
    tgt->status=0;
    tgt->sector_start=0;
    tgt->length=device_size/512;
    strcpy(tgt->target_type, "verity");

    // build the verity params here
    verity_params = buffer + sizeof(struct dm_ioctl) + sizeof(struct dm_target_spec);
    bufsize = DM_BUF_SIZE - (verity_params - buffer);

    if (mode == VERITY_MODE_EIO) {
        // allow operation with older dm-verity drivers that are unaware
        // of the mode parameter by omitting it; this also means that we
        // cannot use logging mode with these drivers, they always cause
        // an I/O error for corrupted blocks
        strcpy(verity_params, table);
    } else if (snprintf(verity_params, bufsize, "%s %d", table, mode) < 0) {
        return -1;
    }

    // set next target boundary
    verity_params += strlen(verity_params) + 1;
    verity_params = (char*) (((unsigned long)verity_params + 7) & ~8);
    tgt->next = verity_params - buffer;

    // send the ioctl to load the verity table
    if (ioctl(fd, DM_TABLE_LOAD, io)) {
        ERROR("Error loading verity table (%s)", strerror(errno));
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

    if (TEMP_FAILURE_RETRY(read(fd, buffer, size)) != size) {
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

static int compare_last_signature(struct fstab_rec *fstab, int *match)
{
    char tag[METADATA_TAG_MAX_LENGTH + 1];
    char *signature = NULL;
    int fd = -1;
    int rc = -1;
    uint8_t curr[SHA256_DIGEST_SIZE];
    uint8_t prev[SHA256_DIGEST_SIZE];
    off64_t offset = 0;
    uint64_t device_size;

    *match = 1;

    // get verity filesystem size
    if (get_fs_size(fstab->fs_type, fstab->blk_device, &device_size) < 0) {
        ERROR("Failed to get filesystem size\n");
        goto out;
    }

    if (read_verity_metadata(device_size, fstab->blk_device, &signature, NULL) < 0) {
        ERROR("Failed to read verity signature from %s\n", fstab->mount_point);
        goto out;
    }

    SHA256_hash(signature, RSANUMBYTES, curr);

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
    free(signature);

    if (fd != -1) {
        close(fd);
    }

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

    /* use the kernel parameter if set */
    property_get("ro.boot.veritymode", propbuf, "");

    if (*propbuf != '\0') {
        if (!strcmp(propbuf, "enforcing")) {
            *mode = VERITY_MODE_DEFAULT;
            return 0;
        } else if (!strcmp(propbuf, "logging")) {
            *mode = VERITY_MODE_LOGGING;
            return 0;
        } else {
            INFO("Unknown value %s for veritymode; ignoring", propbuf);
        }
    }

    if (get_verity_state_offset(fstab, &offset) < 0) {
        /* fall back to stateless behavior */
        *mode = VERITY_MODE_EIO;
        return 0;
    }

    if (was_verity_restart()) {
        /* device was restarted after dm-verity detected a corrupted
         * block, so switch to logging mode */
        *mode = VERITY_MODE_LOGGING;
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

        if (current == VERITY_MODE_LOGGING) {
            *mode = current;
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
    _Alignas(struct dm_ioctl) char buffer[DM_BUF_SIZE];
    char fstab_filename[PROPERTY_VALUE_MAX + sizeof(FSTAB_PREFIX)];
    char *mount_point;
    char propbuf[PROPERTY_VALUE_MAX];
    char *status;
    int fd = -1;
    int i;
    int mode;
    int rc = -1;
    off64_t offset = 0;
    struct dm_ioctl *io = (struct dm_ioctl *) buffer;
    struct fstab *fstab = NULL;

    /* check if we need to store the state */
    property_get("ro.boot.veritymode", propbuf, "");

    if (*propbuf != '\0') {
        return 0; /* state is kept by the bootloader */
    }

    fd = TEMP_FAILURE_RETRY(open("/dev/device-mapper", O_RDWR | O_CLOEXEC));

    if (fd == -1) {
        ERROR("Error opening device mapper (%s)\n", strerror(errno));
        goto out;
    }

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

        if (get_verity_state_offset(&fstab->recs[i], &offset) < 0 ||
            read_verity_state(fstab->recs[i].verity_loc, offset, &mode) < 0) {
            continue;
        }

        mount_point = basename(fstab->recs[i].mount_point);
        verity_ioctl_init(io, mount_point, 0);

        if (ioctl(fd, DM_TABLE_STATUS, io)) {
            ERROR("Failed to query DM_TABLE_STATUS for %s (%s)\n", mount_point,
                strerror(errno));
            continue;
        }

        status = &buffer[io->data_start + sizeof(struct dm_target_spec)];

        if (*status == 'C') {
            if (write_verity_state(fstab->recs[i].verity_loc, offset,
                    VERITY_MODE_LOGGING) < 0) {
                continue;
            }
        }

        if (callback) {
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

int fs_mgr_setup_verity(struct fstab_rec *fstab) {

    int retval = FS_MGR_SETUP_VERITY_FAIL;
    int fd = -1;
    int mode;

    char *verity_blk_name = 0;
    char *verity_table = 0;
    char *verity_table_signature = 0;
    uint64_t device_size = 0;

    _Alignas(struct dm_ioctl) char buffer[DM_BUF_SIZE];
    struct dm_ioctl *io = (struct dm_ioctl *) buffer;
    char *mount_point = basename(fstab->mount_point);

    // set the dm_ioctl flags
    io->flags |= 1;
    io->target_count = 1;

    // get verity filesystem size
    if (get_fs_size(fstab->fs_type, fstab->blk_device, &device_size) < 0) {
        return retval;
    }

    // read the verity block at the end of the block device
    // send error code up the chain so we can detect attempts to disable verity
    retval = read_verity_metadata(device_size,
                                  fstab->blk_device,
                                  &verity_table_signature,
                                  &verity_table);
    if (retval < 0) {
        goto out;
    }

    retval = FS_MGR_SETUP_VERITY_FAIL;

    // get the device mapper fd
    if ((fd = open("/dev/device-mapper", O_RDWR)) < 0) {
        ERROR("Error opening device mapper (%s)", strerror(errno));
        goto out;
    }

    // create the device
    if (create_verity_device(io, mount_point, fd) < 0) {
        ERROR("Couldn't create verity device!");
        goto out;
    }

    // get the name of the device file
    if (get_verity_device_name(io, mount_point, fd, &verity_blk_name) < 0) {
        ERROR("Couldn't get verity device number!");
        goto out;
    }

    // verify the signature on the table
    if (verify_table(verity_table_signature,
                            verity_table,
                            strlen(verity_table)) < 0) {
        goto out;
    }

    if (load_verity_state(fstab, &mode) < 0) {
        /* if accessing or updating the state failed, switch to the default
         * safe mode. This makes sure the device won't end up in an endless
         * restart loop, and no corrupted data will be exposed to userspace
         * without a warning. */
        mode = VERITY_MODE_EIO;
    }

    INFO("Enabling dm-verity for %s (mode %d)\n",  mount_point, mode);

    // load the verity mapping table
    if (load_verity_table(io, mount_point, device_size, fd, verity_table,
            mode) < 0) {
        goto out;
    }

    // activate the device
    if (resume_verity_table(io, mount_point, fd) < 0) {
        goto out;
    }

    // mark the underlying block device as read-only
    fs_mgr_set_blk_ro(fstab->blk_device);

    // assign the new verity block device as the block device
    free(fstab->blk_device);
    fstab->blk_device = verity_blk_name;
    verity_blk_name = 0;

    // make sure we've set everything up properly
    if (test_access(fstab->blk_device) < 0) {
        goto out;
    }

    retval = FS_MGR_SETUP_VERITY_SUCCESS;

out:
    if (fd != -1) {
        close(fd);
    }

    free(verity_table);
    free(verity_table_signature);
    free(verity_blk_name);

    return retval;
}

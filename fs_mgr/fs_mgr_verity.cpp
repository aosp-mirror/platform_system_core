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

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <android-base/file.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <crypto_utils/android_pubkey.h>
#include <cutils/properties.h>
#include <logwrap/logwrap.h>
#include <openssl/obj_mac.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <private/android_filesystem_config.h>

#include "fec/io.h"

#include "fs_mgr.h"
#include "fs_mgr_priv.h"
#include "fs_mgr_priv_dm_ioctl.h"

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

static RSA *load_key(const char *path)
{
    uint8_t key_data[ANDROID_PUBKEY_ENCODED_SIZE];

    FILE* f = fopen(path, "r");
    if (!f) {
        LERROR << "Can't open " << path;
        return NULL;
    }

    if (!fread(key_data, sizeof(key_data), 1, f)) {
        LERROR << "Could not read key!";
        fclose(f);
        return NULL;
    }

    fclose(f);

    RSA* key = NULL;
    if (!android_pubkey_decode(key_data, sizeof(key_data), &key)) {
        LERROR << "Could not parse key!";
        return NULL;
    }

    return key;
}

static int verify_table(const uint8_t *signature, size_t signature_size,
        const char *table, uint32_t table_length)
{
    RSA *key;
    uint8_t hash_buf[SHA256_DIGEST_LENGTH];
    int retval = -1;

    // Hash the table
    SHA256((uint8_t*)table, table_length, hash_buf);

    // Now get the public key from the keyfile
    key = load_key(VERITY_TABLE_RSA_KEY);
    if (!key) {
        LERROR << "Couldn't load verity keys";
        goto out;
    }

    // verify the result
    if (!RSA_verify(NID_sha256, hash_buf, sizeof(hash_buf), signature,
                    signature_size, key)) {
        LERROR << "Couldn't verify table";
        goto out;
    }

    retval = 0;

out:
    RSA_free(key);
    return retval;
}

static int verify_verity_signature(const struct fec_verity_metadata& verity)
{
    if (verify_table(verity.signature, sizeof(verity.signature),
            verity.table, verity.table_length) == 0 ||
        verify_table(verity.ecc_signature, sizeof(verity.ecc_signature),
            verity.table, verity.table_length) == 0) {
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
        LERROR << "Error building verity table; insufficient buffer size?";
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
        LERROR << "Error building verity table; insufficient buffer size?";
        return false;
    }

    return true;
}

static int load_verity_table(struct dm_ioctl *io, const std::string &name,
                             uint64_t device_size, int fd,
        const struct verity_table_params *params, format_verity_table_func format)
{
    char *verity_params;
    char *buffer = (char*) io;
    size_t bufsize;

    fs_mgr_verity_ioctl_init(io, name, DM_STATUS_TABLE_FLAG);

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
        LERROR << "Failed to format verity parameters";
        return -1;
    }

    LINFO << "loading verity table: '" << verity_params << "'";

    // set next target boundary
    verity_params += strlen(verity_params) + 1;
    verity_params = (char*)(((uintptr_t)verity_params + 7) & ~7);
    tgt->next = verity_params - buffer;

    // send the ioctl to load the verity table
    if (ioctl(fd, DM_TABLE_LOAD, io)) {
        PERROR << "Error loading verity table";
        return -1;
    }

    return 0;
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
            PERROR << "Failed to open " << fname;
        }
        goto out;
    }

    if (fstat(fd, &s) == -1) {
        PERROR << "Failed to fstat " << fname;
        goto out;
    }

    size = VERITY_KMSG_BUFSIZE;

    if (size > s.st_size) {
        size = s.st_size;
    }

    if (lseek(fd, s.st_size - size, SEEK_SET) == -1) {
        PERROR << "Failed to lseek " << (intmax_t)(s.st_size - size) << " " << fname;
        goto out;
    }

    if (!android::base::ReadFully(fd, buffer, size)) {
        PERROR << "Failed to read " << size << " bytes from " << fname;
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
        PERROR << "Failed to open " << fname;
        goto out;
    }

    /* check magic */
    if (fseek(fp, start, SEEK_SET) < 0 ||
        fread(&magic, sizeof(magic), 1, fp) != 1) {
        PERROR << "Failed to read magic from " << fname;
        goto out;
    }

    if (magic != METADATA_MAGIC) {
        magic = METADATA_MAGIC;

        if (fseek(fp, start, SEEK_SET) < 0 ||
            fwrite(&magic, sizeof(magic), 1, fp) != 1) {
            PERROR << "Failed to write magic to " << fname;
            goto out;
        }

        rc = metadata_add(fp, start + sizeof(magic), stag, slength, offset);
        if (rc < 0) {
            PERROR << "Failed to add metadata to " << fname;
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
                PERROR << "Failed to seek " << fname;
                goto out;
            }
        } else {
            rc = metadata_add(fp, start, stag, slength, offset);
            if (rc < 0) {
                PERROR << "Failed to write metadata to " << fname;
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
        PERROR << "Failed to open " << fname;
        goto out;
    }

    if (TEMP_FAILURE_RETRY(pwrite64(fd, &s, sizeof(s), offset)) != sizeof(s)) {
        PERROR << "Failed to write " << sizeof(s) << " bytes to " << fname
               << " to offset " << offset;
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
        PERROR << "Failed to open " << fname;
        goto out;
    }

    if (TEMP_FAILURE_RETRY(pread64(fd, &s, sizeof(s), offset)) != sizeof(s)) {
        PERROR << "Failed to read " <<  sizeof(s) << " bytes from " << fname
               << " offset " << offset;
        goto out;
    }

    if (s.header != VERITY_STATE_HEADER) {
        /* space allocated, but no state written. write default state */
        *mode = VERITY_MODE_DEFAULT;
        rc = write_verity_state(fname, offset, *mode);
        goto out;
    }

    if (s.version != VERITY_STATE_VERSION) {
        LERROR << "Unsupported verity state version (" << s.version << ")";
        goto out;
    }

    if (s.mode < VERITY_MODE_EIO ||
        s.mode > VERITY_MODE_LAST) {
        LERROR << "Unsupported verity mode (" << s.mode << ")";
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
        PERROR << "Failed to open " << path;
        return -errno;
    }

    while (size) {
        size_read = TEMP_FAILURE_RETRY(read(fd, buf, READ_BUF_SIZE));
        if (size_read == -1) {
            PERROR << "Error in reading partition " << path;
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
    uint8_t curr[SHA256_DIGEST_LENGTH];
    uint8_t prev[SHA256_DIGEST_LENGTH];

    *match = 1;

    if (fec_open(&f, fstab->blk_device, O_RDONLY, FEC_VERITY_DISABLE,
            FEC_DEFAULT_ROOTS) == -1) {
        PERROR << "Failed to open '" << fstab->blk_device << "'";
        return rc;
    }

    // read verity metadata
    if (fec_verity_get_metadata(f, &verity) == -1) {
        PERROR << "Failed to get verity metadata '" << fstab->blk_device << "'";
        goto out;
    }

    SHA256(verity.signature, sizeof(verity.signature), curr);

    if (snprintf(tag, sizeof(tag), VERITY_LASTSIG_TAG "_%s",
            basename(fstab->mount_point)) >= (int)sizeof(tag)) {
        LERROR << "Metadata tag name too long for " << fstab->mount_point;
        goto out;
    }

    if (metadata_find(fstab->verity_loc, tag, SHA256_DIGEST_LENGTH,
            &offset) < 0) {
        goto out;
    }

    fd = TEMP_FAILURE_RETRY(open(fstab->verity_loc, O_RDWR | O_SYNC | O_CLOEXEC));

    if (fd == -1) {
        PERROR << "Failed to open " << fstab->verity_loc;
        goto out;
    }

    if (TEMP_FAILURE_RETRY(pread64(fd, prev, sizeof(prev),
            offset)) != sizeof(prev)) {
        PERROR << "Failed to read " << sizeof(prev) << " bytes from "
               << fstab->verity_loc << " offset " << offset;
        goto out;
    }

    *match = !memcmp(curr, prev, SHA256_DIGEST_LENGTH);

    if (!*match) {
        /* update current signature hash */
        if (TEMP_FAILURE_RETRY(pwrite64(fd, curr, sizeof(curr),
                offset)) != sizeof(curr)) {
            PERROR << "Failed to write " << sizeof(curr) << " bytes to "
                   << fstab->verity_loc << " offset " << offset;
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
        LERROR << "Metadata tag name too long for " << fstab->mount_point;
        return -1;
    }

    return metadata_find(fstab->verity_loc, tag, sizeof(struct verity_state),
                offset);
}

static int load_verity_state(struct fstab_rec *fstab, int *mode)
{
    int match = 0;
    off64_t offset = 0;

    /* unless otherwise specified, use EIO mode */
    *mode = VERITY_MODE_EIO;

    /* use the kernel parameter if set */
    std::string veritymode;
    if (fs_mgr_get_boot_config("veritymode", &veritymode)) {
        if (veritymode.compare("enforcing")) {
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
    int rc = -1;
    int i;
    int current;
    struct fstab *fstab = NULL;

    /* return the default mode, unless any of the verified partitions are in
     * logging mode, in which case return that */
    *mode = VERITY_MODE_DEFAULT;

    fstab = fs_mgr_read_fstab_default();
    if (!fstab) {
        LERROR << "Failed to read default fstab";
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
    std::string mount_point;
    char propbuf[PROPERTY_VALUE_MAX];
    const char *status;
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
        PERROR << "Error opening device mapper";
        goto out;
    }

    property_get("ro.build.system_root_image", propbuf, "");
    system_root = !strcmp(propbuf, "true");
    fstab = fs_mgr_read_fstab_default();
    if (!fstab) {
        LERROR << "Failed to read default fstab";
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

        fs_mgr_verity_ioctl_init(io, mount_point, 0);

        if (ioctl(fd, DM_TABLE_STATUS, io)) {
            if (fstab->recs[i].fs_mgr_flags & MF_VERIFYATBOOT) {
                status = "V";
            } else {
                PERROR << "Failed to query DM_TABLE_STATUS for "
                       << mount_point.c_str();
                continue;
            }
        }

        status = &buffer[io->data_start + sizeof(struct dm_target_spec)];

        if (*status == 'C' || *status == 'V') {
            callback(&fstab->recs[i], mount_point.c_str(), mode, *status);
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

    for (const auto& token : tokens) {
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

// prepares the verity enabled (MF_VERIFY / MF_VERIFYATBOOT) fstab record for
// mount. The 'wait_for_verity_dev' parameter makes this function wait for the
// verity device to get created before return
int fs_mgr_setup_verity(struct fstab_rec *fstab, bool wait_for_verity_dev)
{
    int retval = FS_MGR_SETUP_VERITY_FAIL;
    int fd = -1;
    std::string verity_blk_name;
    struct fec_handle *f = NULL;
    struct fec_verity_metadata verity;
    struct verity_table_params params = { .table = NULL };

    alignas(dm_ioctl) char buffer[DM_BUF_SIZE];
    struct dm_ioctl *io = (struct dm_ioctl *) buffer;
    const std::string mount_point(basename(fstab->mount_point));
    bool verified_at_boot = false;

    if (fec_open(&f, fstab->blk_device, O_RDONLY, FEC_VERITY_DISABLE,
            FEC_DEFAULT_ROOTS) < 0) {
        PERROR << "Failed to open '" << fstab->blk_device << "'";
        return retval;
    }

    // read verity metadata
    if (fec_verity_get_metadata(f, &verity) < 0) {
        PERROR << "Failed to get verity metadata '" << fstab->blk_device << "'";
        goto out;
    }

#ifdef ALLOW_ADBD_DISABLE_VERITY
    if (verity.disabled) {
        retval = FS_MGR_SETUP_VERITY_DISABLED;
        LINFO << "Attempt to cleanly disable verity - only works in USERDEBUG";
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
        PERROR << "Error opening device mapper";
        goto out;
    }

    // create the device
    if (!fs_mgr_create_verity_device(io, mount_point, fd)) {
        LERROR << "Couldn't create verity device!";
        goto out;
    }

    // get the name of the device file
    if (!fs_mgr_get_verity_device_name(io, mount_point, fd, &verity_blk_name)) {
        LERROR << "Couldn't get verity device number!";
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

    LINFO << "Enabling dm-verity for " << mount_point.c_str()
          << " (mode " << params.mode << ")";

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
        LINFO << "Disabling error correction for " << mount_point.c_str();
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
        LINFO << "Falling back to EIO mode for " << mount_point.c_str();
        params.mode = VERITY_MODE_EIO;

        if (load_verity_table(io, mount_point, verity.data_size, fd, &params,
                format_legacy_verity_table) == 0) {
            goto loaded;
        }
    }

    LERROR << "Failed to load verity table for " << mount_point.c_str();
    goto out;

loaded:

    // activate the device
    if (!fs_mgr_resume_verity_table(io, mount_point, fd)) {
        goto out;
    }

    // mark the underlying block device as read-only
    fs_mgr_set_blk_ro(fstab->blk_device);

    // Verify the entire partition in one go
    // If there is an error, allow it to mount as a normal verity partition.
    if (fstab->fs_mgr_flags & MF_VERIFYATBOOT) {
        LINFO << "Verifying partition " << fstab->blk_device << " at boot";
        int err = read_partition(verity_blk_name.c_str(), verity.data_size);
        if (!err) {
            LINFO << "Verified verity partition "
                  << fstab->blk_device << " at boot";
            verified_at_boot = true;
        }
    }

    // assign the new verity block device as the block device
    if (!verified_at_boot) {
        free(fstab->blk_device);
        fstab->blk_device = strdup(verity_blk_name.c_str());
    } else if (!fs_mgr_destroy_verity_device(io, mount_point, fd)) {
        LERROR << "Failed to remove verity device " << mount_point.c_str();
        goto out;
    }

    // make sure we've set everything up properly
    if (wait_for_verity_dev && fs_mgr_test_access(fstab->blk_device) < 0) {
        goto out;
    }

    retval = FS_MGR_SETUP_VERITY_SUCCESS;

out:
    if (fd != -1) {
        close(fd);
    }

    fec_close(f);
    free(params.table);

    return retval;
}

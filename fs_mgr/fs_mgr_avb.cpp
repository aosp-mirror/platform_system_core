/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <libgen.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

#include <android-base/file.h>
#include <android-base/parseint.h>
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <cutils/properties.h>
#include <libavb/libavb.h>
#include <openssl/sha.h>
#include <sys/ioctl.h>
#include <utils/Compat.h>

#include "fs_mgr.h"
#include "fs_mgr_avb_ops.h"
#include "fs_mgr_priv.h"
#include "fs_mgr_priv_avb.h"
#include "fs_mgr_priv_dm_ioctl.h"
#include "fs_mgr_priv_sha.h"

/* The format of dm-verity construction parameters:
 *     <version> <dev> <hash_dev> <data_block_size> <hash_block_size>
 *     <num_data_blocks> <hash_start_block> <algorithm> <digest> <salt>
 */
#define VERITY_TABLE_FORMAT \
    "%u %s %s %u %u "       \
    "%" PRIu64 " %" PRIu64 " %s %s %s "

#define VERITY_TABLE_PARAMS(hashtree_desc, blk_device, digest, salt)                        \
    hashtree_desc.dm_verity_version, blk_device, blk_device, hashtree_desc.data_block_size, \
        hashtree_desc.hash_block_size,                                                      \
        hashtree_desc.image_size / hashtree_desc.data_block_size,  /* num_data_blocks. */   \
        hashtree_desc.tree_offset / hashtree_desc.hash_block_size, /* hash_start_block. */  \
        (char*)hashtree_desc.hash_algorithm, digest, salt

#define VERITY_TABLE_OPT_RESTART "restart_on_corruption"
#define VERITY_TABLE_OPT_IGNZERO "ignore_zero_blocks"

/* The default format of dm-verity optional parameters:
 *     <#opt_params> ignore_zero_blocks restart_on_corruption
 */
#define VERITY_TABLE_OPT_DEFAULT_FORMAT "2 %s %s"
#define VERITY_TABLE_OPT_DEFAULT_PARAMS VERITY_TABLE_OPT_IGNZERO, VERITY_TABLE_OPT_RESTART

/* The FEC (forward error correction) format of dm-verity optional parameters:
 *     <#opt_params> use_fec_from_device <fec_dev>
 *     fec_roots <num> fec_blocks <num> fec_start <offset>
 *     ignore_zero_blocks restart_on_corruption
 */
#define VERITY_TABLE_OPT_FEC_FORMAT \
    "10 use_fec_from_device %s fec_roots %u fec_blocks %" PRIu64 " fec_start %" PRIu64 " %s %s"

/* Note that fec_blocks is the size that FEC covers, *not* the
 * size of the FEC data. Since we use FEC for everything up until
 * the FEC data, it's the same as the offset (fec_start).
 */
#define VERITY_TABLE_OPT_FEC_PARAMS(hashtree_desc, blk_device)                     \
    blk_device, hashtree_desc.fec_num_roots,                                       \
        hashtree_desc.fec_offset / hashtree_desc.data_block_size, /* fec_blocks */ \
        hashtree_desc.fec_offset / hashtree_desc.data_block_size, /* fec_start */  \
        VERITY_TABLE_OPT_IGNZERO, VERITY_TABLE_OPT_RESTART

AvbSlotVerifyData* fs_mgr_avb_verify_data = nullptr;
AvbOps* fs_mgr_avb_ops = nullptr;

enum HashAlgorithm {
    kInvalid = 0,
    kSHA256 = 1,
    kSHA512 = 2,
};

struct androidboot_vbmeta {
    HashAlgorithm hash_alg;
    uint8_t digest[SHA512_DIGEST_LENGTH];
    size_t vbmeta_size;
    bool allow_verification_error;
};

androidboot_vbmeta fs_mgr_vbmeta_prop;

static inline bool nibble_value(const char& c, uint8_t* value) {
    FS_MGR_CHECK(value != nullptr);

    switch (c) {
        case '0' ... '9':
            *value = c - '0';
            break;
        case 'a' ... 'f':
            *value = c - 'a' + 10;
            break;
        case 'A' ... 'F':
            *value = c - 'A' + 10;
            break;
        default:
            return false;
    }

    return true;
}

static bool hex_to_bytes(uint8_t* bytes, size_t bytes_len, const std::string& hex) {
    FS_MGR_CHECK(bytes != nullptr);

    if (hex.size() % 2 != 0) {
        return false;
    }
    if (hex.size() / 2 > bytes_len) {
        return false;
    }
    for (size_t i = 0, j = 0, n = hex.size(); i < n; i += 2, ++j) {
        uint8_t high;
        if (!nibble_value(hex[i], &high)) {
            return false;
        }
        uint8_t low;
        if (!nibble_value(hex[i + 1], &low)) {
            return false;
        }
        bytes[j] = (high << 4) | low;
    }
    return true;
}

static std::string bytes_to_hex(const uint8_t* bytes, size_t bytes_len) {
    FS_MGR_CHECK(bytes != nullptr);

    static const char* hex_digits = "0123456789abcdef";
    std::string hex;

    for (size_t i = 0; i < bytes_len; i++) {
        hex.push_back(hex_digits[(bytes[i] & 0xF0) >> 4]);
        hex.push_back(hex_digits[bytes[i] & 0x0F]);
    }
    return hex;
}

static bool load_vbmeta_prop(androidboot_vbmeta* vbmeta_prop) {
    FS_MGR_CHECK(vbmeta_prop != nullptr);

    std::string cmdline;
    android::base::ReadFileToString("/proc/cmdline", &cmdline);

    std::string hash_alg;
    std::string digest;

    for (const auto& entry : android::base::Split(android::base::Trim(cmdline), " ")) {
        std::vector<std::string> pieces = android::base::Split(entry, "=");
        const std::string& key = pieces[0];
        const std::string& value = pieces[1];

        if (key == "androidboot.vbmeta.device_state") {
            vbmeta_prop->allow_verification_error = (value == "unlocked");
        } else if (key == "androidboot.vbmeta.hash_alg") {
            hash_alg = value;
        } else if (key == "androidboot.vbmeta.size") {
            if (!android::base::ParseUint(value.c_str(), &vbmeta_prop->vbmeta_size)) {
                return false;
            }
        } else if (key == "androidboot.vbmeta.digest") {
            digest = value;
        }
    }

    // Reads hash algorithm.
    size_t expected_digest_size = 0;
    if (hash_alg == "sha256") {
        expected_digest_size = SHA256_DIGEST_LENGTH * 2;
        vbmeta_prop->hash_alg = kSHA256;
    } else if (hash_alg == "sha512") {
        expected_digest_size = SHA512_DIGEST_LENGTH * 2;
        vbmeta_prop->hash_alg = kSHA512;
    } else {
        LERROR << "Unknown hash algorithm: " << hash_alg.c_str();
        return false;
    }

    // Reads digest.
    if (digest.size() != expected_digest_size) {
        LERROR << "Unexpected digest size: " << digest.size()
               << " (expected: " << expected_digest_size << ")";
        return false;
    }

    if (!hex_to_bytes(vbmeta_prop->digest, sizeof(vbmeta_prop->digest), digest)) {
        LERROR << "Hash digest contains non-hexidecimal character: " << digest.c_str();
        return false;
    }

    return true;
}

template <typename Hasher>
static std::pair<size_t, bool> verify_vbmeta_digest(const AvbSlotVerifyData& verify_data,
                                                    const androidboot_vbmeta& vbmeta_prop) {
    size_t total_size = 0;
    Hasher hasher;
    for (size_t n = 0; n < verify_data.num_vbmeta_images; n++) {
        hasher.update(verify_data.vbmeta_images[n].vbmeta_data,
                      verify_data.vbmeta_images[n].vbmeta_size);
        total_size += verify_data.vbmeta_images[n].vbmeta_size;
    }

    bool matched = (memcmp(hasher.finalize(), vbmeta_prop.digest, Hasher::DIGEST_SIZE) == 0);

    return std::make_pair(total_size, matched);
}

static bool verify_vbmeta_images(const AvbSlotVerifyData& verify_data,
                                 const androidboot_vbmeta& vbmeta_prop) {
    if (verify_data.num_vbmeta_images == 0) {
        LERROR << "No vbmeta images";
        return false;
    }

    size_t total_size = 0;
    bool digest_matched = false;

    if (vbmeta_prop.hash_alg == kSHA256) {
        std::tie(total_size, digest_matched) =
            verify_vbmeta_digest<SHA256Hasher>(verify_data, vbmeta_prop);
    } else if (vbmeta_prop.hash_alg == kSHA512) {
        std::tie(total_size, digest_matched) =
            verify_vbmeta_digest<SHA512Hasher>(verify_data, vbmeta_prop);
    }

    if (total_size != vbmeta_prop.vbmeta_size) {
        LERROR << "total vbmeta size mismatch: " << total_size
               << " (expected: " << vbmeta_prop.vbmeta_size << ")";
        return false;
    }

    if (!digest_matched) {
        LERROR << "vbmeta digest mismatch";
        return false;
    }

    return true;
}

static bool hashtree_load_verity_table(struct dm_ioctl* io, const std::string& dm_device_name,
                                       int fd, const std::string& blk_device,
                                       const AvbHashtreeDescriptor& hashtree_desc,
                                       const std::string& salt, const std::string& root_digest) {
    fs_mgr_verity_ioctl_init(io, dm_device_name, DM_STATUS_TABLE_FLAG);

    // The buffer consists of [dm_ioctl][dm_target_spec][verity_params].
    char* buffer = (char*)io;

    // Builds the dm_target_spec arguments.
    struct dm_target_spec* dm_target = (struct dm_target_spec*)&buffer[sizeof(struct dm_ioctl)];
    io->target_count = 1;
    dm_target->status = 0;
    dm_target->sector_start = 0;
    dm_target->length = hashtree_desc.image_size / 512;
    strcpy(dm_target->target_type, "verity");

    // Builds the verity params.
    char* verity_params = buffer + sizeof(struct dm_ioctl) + sizeof(struct dm_target_spec);
    size_t bufsize = DM_BUF_SIZE - (verity_params - buffer);

    int res = 0;
    if (hashtree_desc.fec_size > 0) {
        res = snprintf(verity_params, bufsize, VERITY_TABLE_FORMAT VERITY_TABLE_OPT_FEC_FORMAT,
                       VERITY_TABLE_PARAMS(hashtree_desc, blk_device.c_str(), root_digest.c_str(),
                                           salt.c_str()),
                       VERITY_TABLE_OPT_FEC_PARAMS(hashtree_desc, blk_device.c_str()));
    } else {
        res = snprintf(verity_params, bufsize, VERITY_TABLE_FORMAT VERITY_TABLE_OPT_DEFAULT_FORMAT,
                       VERITY_TABLE_PARAMS(hashtree_desc, blk_device.c_str(), root_digest.c_str(),
                                           salt.c_str()),
                       VERITY_TABLE_OPT_DEFAULT_PARAMS);
    }

    if (res < 0 || (size_t)res >= bufsize) {
        LERROR << "Error building verity table; insufficient buffer size?";
        return false;
    }

    LINFO << "Loading verity table: '" << verity_params << "'";

    // Sets ext target boundary.
    verity_params += strlen(verity_params) + 1;
    verity_params = (char*)(((unsigned long)verity_params + 7) & ~7);
    dm_target->next = verity_params - buffer;

    // Sends the ioctl to load the verity table.
    if (ioctl(fd, DM_TABLE_LOAD, io)) {
        PERROR << "Error loading verity table";
        return false;
    }

    return true;
}

static bool hashtree_dm_verity_setup(struct fstab_rec* fstab_entry,
                                     const AvbHashtreeDescriptor& hashtree_desc,
                                     const std::string& salt, const std::string& root_digest) {
    // Gets the device mapper fd.
    android::base::unique_fd fd(open("/dev/device-mapper", O_RDWR));
    if (fd < 0) {
        PERROR << "Error opening device mapper";
        return false;
    }

    // Creates the device.
    alignas(dm_ioctl) char buffer[DM_BUF_SIZE];
    struct dm_ioctl* io = (struct dm_ioctl*)buffer;
    const std::string mount_point(basename(fstab_entry->mount_point));
    if (!fs_mgr_create_verity_device(io, mount_point, fd)) {
        LERROR << "Couldn't create verity device!";
        return false;
    }

    // Gets the name of the device file.
    std::string verity_blk_name;
    if (!fs_mgr_get_verity_device_name(io, mount_point, fd, &verity_blk_name)) {
        LERROR << "Couldn't get verity device number!";
        return false;
    }

    // Loads the verity mapping table.
    if (!hashtree_load_verity_table(io, mount_point, fd, std::string(fstab_entry->blk_device),
                                    hashtree_desc, salt, root_digest)) {
        LERROR << "Couldn't load verity table!";
        return false;
    }

    // Activates the device.
    if (!fs_mgr_resume_verity_table(io, mount_point, fd)) {
        return false;
    }

    // Marks the underlying block device as read-only.
    fs_mgr_set_blk_ro(fstab_entry->blk_device);

    // TODO(bowgotsai): support verified all partition at boot.
    // Updates fstab_rec->blk_device to verity device name.
    free(fstab_entry->blk_device);
    fstab_entry->blk_device = strdup(verity_blk_name.c_str());

    // Makes sure we've set everything up properly.
    if (fs_mgr_test_access(verity_blk_name.c_str()) < 0) {
        return false;
    }

    return true;
}

static bool get_hashtree_descriptor(const std::string& partition_name,
                                    const AvbSlotVerifyData& verify_data,
                                    AvbHashtreeDescriptor* out_hashtree_desc, std::string* out_salt,
                                    std::string* out_digest) {
    bool found = false;
    const uint8_t* desc_partition_name;

    for (size_t i = 0; i < verify_data.num_vbmeta_images && !found; i++) {
        // Get descriptors from vbmeta_images[i].
        size_t num_descriptors;
        std::unique_ptr<const AvbDescriptor* [], decltype(&avb_free)> descriptors(
            avb_descriptor_get_all(verify_data.vbmeta_images[i].vbmeta_data,
                                   verify_data.vbmeta_images[i].vbmeta_size, &num_descriptors),
            avb_free);

        if (!descriptors || num_descriptors < 1) {
            continue;
        }

        // Ensures that hashtree descriptor is either in /vbmeta or in
        // the same partition for verity setup.
        std::string vbmeta_partition_name(verify_data.vbmeta_images[i].partition_name);
        if (vbmeta_partition_name != "vbmeta" && vbmeta_partition_name != partition_name) {
            LWARNING << "Skip vbmeta image at " << verify_data.vbmeta_images[i].partition_name
                     << " for partition: " << partition_name.c_str();
            continue;
        }

        for (size_t j = 0; j < num_descriptors && !found; j++) {
            AvbDescriptor desc;
            if (!avb_descriptor_validate_and_byteswap(descriptors[j], &desc)) {
                LWARNING << "Descriptor[" << j << "] is invalid";
                continue;
            }
            if (desc.tag == AVB_DESCRIPTOR_TAG_HASHTREE) {
                desc_partition_name =
                    (const uint8_t*)descriptors[j] + sizeof(AvbHashtreeDescriptor);
                if (!avb_hashtree_descriptor_validate_and_byteswap(
                        (AvbHashtreeDescriptor*)descriptors[j], out_hashtree_desc)) {
                    continue;
                }
                if (out_hashtree_desc->partition_name_len != partition_name.length()) {
                    continue;
                }
                // Notes that desc_partition_name is not NUL-terminated.
                std::string hashtree_partition_name((const char*)desc_partition_name,
                                                    out_hashtree_desc->partition_name_len);
                if (hashtree_partition_name == partition_name) {
                    found = true;
                }
            }
        }
    }

    if (!found) {
        LERROR << "Partition descriptor not found: " << partition_name.c_str();
        return false;
    }

    const uint8_t* desc_salt = desc_partition_name + out_hashtree_desc->partition_name_len;
    *out_salt = bytes_to_hex(desc_salt, out_hashtree_desc->salt_len);

    const uint8_t* desc_digest = desc_salt + out_hashtree_desc->salt_len;
    *out_digest = bytes_to_hex(desc_digest, out_hashtree_desc->root_digest_len);

    return true;
}

static bool init_is_avb_used() {
    // When AVB is used, boot loader should set androidboot.vbmeta.{hash_alg,
    // size, digest} in kernel cmdline or in device tree. They will then be
    // imported by init process to system properties: ro.boot.vbmeta.{hash_alg, size, digest}.
    //
    // In case of early mount, init properties are not initialized, so we also
    // ensure we look into kernel command line and device tree if the property is
    // not found
    //
    // Checks hash_alg as an indicator for whether AVB is used.
    // We don't have to parse and check all of them here. The check will
    // be done in fs_mgr_load_vbmeta_images() and FS_MGR_SETUP_AVB_FAIL will
    // be returned when there is an error.

    std::string hash_alg;
    if (fs_mgr_get_boot_config("vbmeta.hash_alg", &hash_alg) == 0) {
        if (hash_alg == "sha256" || hash_alg == "sha512") {
            return true;
        }
    }

    return false;
}

bool fs_mgr_is_avb_used() {
    static bool result = init_is_avb_used();
    return result;
}

int fs_mgr_load_vbmeta_images(struct fstab* fstab) {
    FS_MGR_CHECK(fstab != nullptr);

    // Gets the expected hash value of vbmeta images from
    // kernel cmdline.
    if (!load_vbmeta_prop(&fs_mgr_vbmeta_prop)) {
        return FS_MGR_SETUP_AVB_FAIL;
    }

    fs_mgr_avb_ops = fs_mgr_dummy_avb_ops_new(fstab);
    if (fs_mgr_avb_ops == nullptr) {
        LERROR << "Failed to allocate dummy avb_ops";
        return FS_MGR_SETUP_AVB_FAIL;
    }

    // Invokes avb_slot_verify() to load and verify all vbmeta images.
    // Sets requested_partitions to nullptr as it's to copy the contents
    // of HASH partitions into fs_mgr_avb_verify_data, which is not required as
    // fs_mgr only deals with HASHTREE partitions.
    const char *requested_partitions[] = {nullptr};
    std::string ab_suffix;
    fs_mgr_get_boot_config("slot_suffix", &ab_suffix);
    AvbSlotVerifyResult verify_result =
        avb_slot_verify(fs_mgr_avb_ops, requested_partitions, ab_suffix.c_str(),
                        fs_mgr_vbmeta_prop.allow_verification_error, &fs_mgr_avb_verify_data);

    // Only allow two verify results:
    //   - AVB_SLOT_VERIFY_RESULT_OK.
    //   - AVB_SLOT_VERIFY_RESULT_ERROR_VERIFICATION (for UNLOCKED state).
    if (verify_result == AVB_SLOT_VERIFY_RESULT_ERROR_VERIFICATION) {
        if (!fs_mgr_vbmeta_prop.allow_verification_error) {
            LERROR << "ERROR_VERIFICATION isn't allowed";
            goto fail;
        }
    } else if (verify_result != AVB_SLOT_VERIFY_RESULT_OK) {
        LERROR << "avb_slot_verify failed, result: " << verify_result;
        goto fail;
    }

    // Verifies vbmeta images against the digest passed from bootloader.
    if (!verify_vbmeta_images(*fs_mgr_avb_verify_data, fs_mgr_vbmeta_prop)) {
        LERROR << "verify_vbmeta_images failed";
        goto fail;
    } else {
        // Checks whether FLAGS_HASHTREE_DISABLED is set.
        AvbVBMetaImageHeader vbmeta_header;
        avb_vbmeta_image_header_to_host_byte_order(
            (AvbVBMetaImageHeader*)fs_mgr_avb_verify_data->vbmeta_images[0].vbmeta_data,
            &vbmeta_header);

        bool hashtree_disabled =
            ((AvbVBMetaImageFlags)vbmeta_header.flags & AVB_VBMETA_IMAGE_FLAGS_HASHTREE_DISABLED);
        if (hashtree_disabled) {
            return FS_MGR_SETUP_AVB_HASHTREE_DISABLED;
        }
    }

    if (verify_result == AVB_SLOT_VERIFY_RESULT_OK) {
        return FS_MGR_SETUP_AVB_SUCCESS;
    }

fail:
    fs_mgr_unload_vbmeta_images();
    return FS_MGR_SETUP_AVB_FAIL;
}

void fs_mgr_unload_vbmeta_images() {
    if (fs_mgr_avb_verify_data != nullptr) {
        avb_slot_verify_data_free(fs_mgr_avb_verify_data);
    }

    if (fs_mgr_avb_ops != nullptr) {
        fs_mgr_dummy_avb_ops_free(fs_mgr_avb_ops);
    }
}

int fs_mgr_setup_avb(struct fstab_rec* fstab_entry) {
    if (!fstab_entry || !fs_mgr_avb_verify_data || fs_mgr_avb_verify_data->num_vbmeta_images < 1) {
        return FS_MGR_SETUP_AVB_FAIL;
    }

    std::string partition_name(basename(fstab_entry->mount_point));
    if (!avb_validate_utf8((const uint8_t*)partition_name.c_str(), partition_name.length())) {
        LERROR << "Partition name: " << partition_name.c_str() << " is not valid UTF-8.";
        return FS_MGR_SETUP_AVB_FAIL;
    }

    AvbHashtreeDescriptor hashtree_descriptor;
    std::string salt;
    std::string root_digest;
    if (!get_hashtree_descriptor(partition_name, *fs_mgr_avb_verify_data, &hashtree_descriptor,
                                 &salt, &root_digest)) {
        return FS_MGR_SETUP_AVB_FAIL;
    }

    // Converts HASHTREE descriptor to verity_table_params.
    if (!hashtree_dm_verity_setup(fstab_entry, hashtree_descriptor, salt, root_digest)) {
        return FS_MGR_SETUP_AVB_FAIL;
    }

    return FS_MGR_SETUP_AVB_SUCCESS;
}

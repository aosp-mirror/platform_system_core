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
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <cutils/properties.h>
#include <libavb/libavb.h>
#include <openssl/sha.h>
#include <sys/ioctl.h>
#include <utils/Compat.h>

#include "fs_mgr.h"
#include "fs_mgr_avb.h"
#include "fs_mgr_avb_ops.h"
#include "fs_mgr_priv.h"
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

template <typename Hasher>
static std::pair<size_t, bool> verify_vbmeta_digest(const AvbSlotVerifyData& verify_data,
                                                    const uint8_t* expected_digest) {
    size_t total_size = 0;
    Hasher hasher;
    for (size_t n = 0; n < verify_data.num_vbmeta_images; n++) {
        hasher.update(verify_data.vbmeta_images[n].vbmeta_data,
                      verify_data.vbmeta_images[n].vbmeta_size);
        total_size += verify_data.vbmeta_images[n].vbmeta_size;
    }

    bool matched = (memcmp(hasher.finalize(), expected_digest, Hasher::DIGEST_SIZE) == 0);

    return std::make_pair(total_size, matched);
}

// Reads the following values from kernel cmdline and provides the
// VerifyVbmetaImages() to verify AvbSlotVerifyData.
//   - androidboot.vbmeta.device_state
//   - androidboot.vbmeta.hash_alg
//   - androidboot.vbmeta.size
//   - androidboot.vbmeta.digest
class FsManagerAvbVerifier {
  public:
    // The factory method to return a unique_ptr<FsManagerAvbVerifier>
    static std::unique_ptr<FsManagerAvbVerifier> Create();
    bool VerifyVbmetaImages(const AvbSlotVerifyData& verify_data);
    bool IsDeviceUnlocked() { return is_device_unlocked_; }

  protected:
    FsManagerAvbVerifier() = default;

  private:
    enum HashAlgorithm {
        kInvalid = 0,
        kSHA256 = 1,
        kSHA512 = 2,
    };

    HashAlgorithm hash_alg_;
    uint8_t digest_[SHA512_DIGEST_LENGTH];
    size_t vbmeta_size_;
    bool is_device_unlocked_;
};

std::unique_ptr<FsManagerAvbVerifier> FsManagerAvbVerifier::Create() {
    std::string cmdline;
    if (!android::base::ReadFileToString("/proc/cmdline", &cmdline)) {
        LERROR << "Failed to read /proc/cmdline";
        return nullptr;
    }

    std::unique_ptr<FsManagerAvbVerifier> avb_verifier(new FsManagerAvbVerifier());
    if (!avb_verifier) {
        LERROR << "Failed to create unique_ptr<FsManagerAvbVerifier>";
        return nullptr;
    }

    std::string digest;
    std::string hash_alg;
    for (const auto& entry : android::base::Split(android::base::Trim(cmdline), " ")) {
        std::vector<std::string> pieces = android::base::Split(entry, "=");
        const std::string& key = pieces[0];
        const std::string& value = pieces[1];

        if (key == "androidboot.vbmeta.device_state") {
            avb_verifier->is_device_unlocked_ = (value == "unlocked");
        } else if (key == "androidboot.vbmeta.hash_alg") {
            hash_alg = value;
        } else if (key == "androidboot.vbmeta.size") {
            if (!android::base::ParseUint(value.c_str(), &avb_verifier->vbmeta_size_)) {
                return nullptr;
            }
        } else if (key == "androidboot.vbmeta.digest") {
            digest = value;
        }
    }

    // Reads hash algorithm.
    size_t expected_digest_size = 0;
    if (hash_alg == "sha256") {
        expected_digest_size = SHA256_DIGEST_LENGTH * 2;
        avb_verifier->hash_alg_ = kSHA256;
    } else if (hash_alg == "sha512") {
        expected_digest_size = SHA512_DIGEST_LENGTH * 2;
        avb_verifier->hash_alg_ = kSHA512;
    } else {
        LERROR << "Unknown hash algorithm: " << hash_alg.c_str();
        return nullptr;
    }

    // Reads digest.
    if (digest.size() != expected_digest_size) {
        LERROR << "Unexpected digest size: " << digest.size()
               << " (expected: " << expected_digest_size << ")";
        return nullptr;
    }

    if (!hex_to_bytes(avb_verifier->digest_, sizeof(avb_verifier->digest_), digest)) {
        LERROR << "Hash digest contains non-hexidecimal character: " << digest.c_str();
        return nullptr;
    }

    return avb_verifier;
}

bool FsManagerAvbVerifier::VerifyVbmetaImages(const AvbSlotVerifyData& verify_data) {
    if (verify_data.num_vbmeta_images == 0) {
        LERROR << "No vbmeta images";
        return false;
    }

    size_t total_size = 0;
    bool digest_matched = false;

    if (hash_alg_ == kSHA256) {
        std::tie(total_size, digest_matched) =
            verify_vbmeta_digest<SHA256Hasher>(verify_data, digest_);
    } else if (hash_alg_ == kSHA512) {
        std::tie(total_size, digest_matched) =
            verify_vbmeta_digest<SHA512Hasher>(verify_data, digest_);
    }

    if (total_size != vbmeta_size_) {
        LERROR << "total vbmeta size mismatch: " << total_size << " (expected: " << vbmeta_size_
               << ")";
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
                                     const std::string& salt, const std::string& root_digest,
                                     bool wait_for_verity_dev) {
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

    // Updates fstab_rec->blk_device to verity device name.
    free(fstab_entry->blk_device);
    fstab_entry->blk_device = strdup(verity_blk_name.c_str());

    // Makes sure we've set everything up properly.
    if (wait_for_verity_dev && fs_mgr_test_access(verity_blk_name.c_str()) < 0) {
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

        // Ensures that hashtree descriptor is in /vbmeta or /boot or in
        // the same partition for verity setup.
        std::string vbmeta_partition_name(verify_data.vbmeta_images[i].partition_name);
        if (vbmeta_partition_name != "vbmeta" &&
            vbmeta_partition_name != "boot" &&  // for legacy device to append top-level vbmeta
            vbmeta_partition_name != partition_name) {
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
                desc_partition_name = (const uint8_t*)descriptors[j] + sizeof(AvbHashtreeDescriptor);
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

FsManagerAvbUniquePtr FsManagerAvbHandle::Open(const std::string& device_file_by_name_prefix) {
    if (device_file_by_name_prefix.empty()) {
        LERROR << "Missing device file by-name prefix";
        return nullptr;
    }

    // Gets the expected hash value of vbmeta images from kernel cmdline.
    std::unique_ptr<FsManagerAvbVerifier> avb_verifier = FsManagerAvbVerifier::Create();
    if (!avb_verifier) {
        LERROR << "Failed to create FsManagerAvbVerifier";
        return nullptr;
    }

    FsManagerAvbUniquePtr avb_handle(new FsManagerAvbHandle());
    if (!avb_handle) {
        LERROR << "Failed to allocate FsManagerAvbHandle";
        return nullptr;
    }

    FsManagerAvbOps avb_ops(device_file_by_name_prefix);
    AvbSlotVerifyResult verify_result = avb_ops.AvbSlotVerify(
        fs_mgr_get_slot_suffix(), avb_verifier->IsDeviceUnlocked(), &avb_handle->avb_slot_data_);

    // Only allow two verify results:
    //   - AVB_SLOT_VERIFY_RESULT_OK.
    //   - AVB_SLOT_VERIFY_RESULT_ERROR_VERIFICATION (for UNLOCKED state).
    if (verify_result == AVB_SLOT_VERIFY_RESULT_ERROR_VERIFICATION) {
        if (!avb_verifier->IsDeviceUnlocked()) {
            LERROR << "ERROR_VERIFICATION isn't allowed";
            return nullptr;
        }
    } else if (verify_result != AVB_SLOT_VERIFY_RESULT_OK) {
        LERROR << "avb_slot_verify failed, result: " << verify_result;
        return nullptr;
    }

    // Sets the MAJOR.MINOR for init to set it into "ro.boot.avb_version".
    avb_handle->avb_version_ =
        android::base::StringPrintf("%d.%d", AVB_VERSION_MAJOR, AVB_VERSION_MINOR);

    // Verifies vbmeta images against the digest passed from bootloader.
    if (!avb_verifier->VerifyVbmetaImages(*avb_handle->avb_slot_data_)) {
        LERROR << "VerifyVbmetaImages failed";
        return nullptr;
    } else {
        // Checks whether FLAGS_HASHTREE_DISABLED is set.
        AvbVBMetaImageHeader vbmeta_header;
        avb_vbmeta_image_header_to_host_byte_order(
            (AvbVBMetaImageHeader*)avb_handle->avb_slot_data_->vbmeta_images[0].vbmeta_data,
            &vbmeta_header);

        bool hashtree_disabled =
            ((AvbVBMetaImageFlags)vbmeta_header.flags & AVB_VBMETA_IMAGE_FLAGS_HASHTREE_DISABLED);
        if (hashtree_disabled) {
            avb_handle->status_ = kFsManagerAvbHandleHashtreeDisabled;
            return avb_handle;
        }
    }

    if (verify_result == AVB_SLOT_VERIFY_RESULT_OK) {
        avb_handle->status_ = kFsManagerAvbHandleSuccess;
        return avb_handle;
    }
    return nullptr;
}

bool FsManagerAvbHandle::SetUpAvb(struct fstab_rec* fstab_entry, bool wait_for_verity_dev) {
    if (!fstab_entry) return false;
    if (!avb_slot_data_ || avb_slot_data_->num_vbmeta_images < 1) {
        return false;
    }
    if (status_ == kFsManagerAvbHandleHashtreeDisabled) {
        LINFO << "AVB HASHTREE disabled on:" << fstab_entry->mount_point;
        return true;
    }
    if (status_ != kFsManagerAvbHandleSuccess) return false;

    std::string partition_name(basename(fstab_entry->mount_point));
    if (!avb_validate_utf8((const uint8_t*)partition_name.c_str(), partition_name.length())) {
        LERROR << "Partition name: " << partition_name.c_str() << " is not valid UTF-8.";
        return false;
    }

    AvbHashtreeDescriptor hashtree_descriptor;
    std::string salt;
    std::string root_digest;
    if (!get_hashtree_descriptor(partition_name, *avb_slot_data_, &hashtree_descriptor, &salt,
                                 &root_digest)) {
        return false;
    }

    // Converts HASHTREE descriptor to verity_table_params.
    if (!hashtree_dm_verity_setup(fstab_entry, hashtree_descriptor, salt, root_digest,
                                  wait_for_verity_dev)) {
        return false;
    }
    return true;
}

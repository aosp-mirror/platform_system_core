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

#include "fs_mgr_avb.h"

#include <fcntl.h>
#include <libgen.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>

#include <sstream>
#include <string>
#include <vector>

#include <android-base/file.h>
#include <android-base/parseint.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <libavb/libavb.h>
#include <libdm/dm.h>

#include "fs_mgr.h"
#include "fs_mgr_priv.h"
#include "fs_mgr_priv_avb_ops.h"
#include "fs_mgr_priv_sha.h"

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
//   - androidboot.vbmeta.hash_alg
//   - androidboot.vbmeta.size
//   - androidboot.vbmeta.digest
class FsManagerAvbVerifier {
  public:
    // The factory method to return a unique_ptr<FsManagerAvbVerifier>
    static std::unique_ptr<FsManagerAvbVerifier> Create();
    bool VerifyVbmetaImages(const AvbSlotVerifyData& verify_data);

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
};

std::unique_ptr<FsManagerAvbVerifier> FsManagerAvbVerifier::Create() {
    std::unique_ptr<FsManagerAvbVerifier> avb_verifier(new FsManagerAvbVerifier());
    if (!avb_verifier) {
        LERROR << "Failed to create unique_ptr<FsManagerAvbVerifier>";
        return nullptr;
    }

    std::string value;
    if (!fs_mgr_get_boot_config("vbmeta.size", &value) ||
        !android::base::ParseUint(value.c_str(), &avb_verifier->vbmeta_size_)) {
        LERROR << "Invalid hash size: " << value.c_str();
        return nullptr;
    }

    // Reads hash algorithm.
    size_t expected_digest_size = 0;
    std::string hash_alg;
    fs_mgr_get_boot_config("vbmeta.hash_alg", &hash_alg);
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
    std::string digest;
    fs_mgr_get_boot_config("vbmeta.digest", &digest);
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

// Constructs dm-verity arguments for sending DM_TABLE_LOAD ioctl to kernel.
// See the following link for more details:
// https://gitlab.com/cryptsetup/cryptsetup/wikis/DMVerity
static bool construct_verity_table(const AvbHashtreeDescriptor& hashtree_desc,
                                   const std::string& salt, const std::string& root_digest,
                                   const std::string& blk_device, android::dm::DmTable* table) {
    // Loads androidboot.veritymode from kernel cmdline.
    std::string verity_mode;
    if (!fs_mgr_get_boot_config("veritymode", &verity_mode)) {
        verity_mode = "enforcing";  // Defaults to enforcing when it's absent.
    }

    // Converts veritymode to the format used in kernel.
    std::string dm_verity_mode;
    if (verity_mode == "enforcing") {
        dm_verity_mode = "restart_on_corruption";
    } else if (verity_mode == "logging") {
        dm_verity_mode = "ignore_corruption";
    } else if (verity_mode != "eio") {  // Default dm_verity_mode is eio.
        LERROR << "Unknown androidboot.veritymode: " << verity_mode;
        return false;
    }

    std::ostringstream hash_algorithm;
    hash_algorithm << hashtree_desc.hash_algorithm;

    android::dm::DmTargetVerity target(0, hashtree_desc.image_size / 512,
                                       hashtree_desc.dm_verity_version, blk_device, blk_device,
                                       hashtree_desc.data_block_size, hashtree_desc.hash_block_size,
                                       hashtree_desc.image_size / hashtree_desc.data_block_size,
                                       hashtree_desc.tree_offset / hashtree_desc.hash_block_size,
                                       hash_algorithm.str(), root_digest, salt);
    if (hashtree_desc.fec_size > 0) {
        target.UseFec(blk_device, hashtree_desc.fec_num_roots,
                      hashtree_desc.fec_offset / hashtree_desc.data_block_size,
                      hashtree_desc.fec_offset / hashtree_desc.data_block_size);
    }
    if (!dm_verity_mode.empty()) {
        target.SetVerityMode(dm_verity_mode);
    }
    // Always use ignore_zero_blocks.
    target.IgnoreZeroBlocks();

    LINFO << "Built verity table: '" << target.GetParameterString() << "'";

    return table->AddTarget(std::make_unique<android::dm::DmTargetVerity>(target));
}

static bool hashtree_dm_verity_setup(struct fstab_rec* fstab_entry,
                                     const AvbHashtreeDescriptor& hashtree_desc,
                                     const std::string& salt, const std::string& root_digest,
                                     bool wait_for_verity_dev) {
    android::dm::DmTable table;
    if (!construct_verity_table(hashtree_desc, salt, root_digest, fstab_entry->blk_device, &table) ||
        !table.valid()) {
        LERROR << "Failed to construct verity table.";
        return false;
    }
    table.set_readonly(true);

    const std::string mount_point(basename(fstab_entry->mount_point));
    android::dm::DeviceMapper& dm = android::dm::DeviceMapper::Instance();
    if (!dm.CreateDevice(mount_point, table)) {
        LERROR << "Couldn't create verity device!";
        return false;
    }

    std::string dev_path;
    if (!dm.GetDmDevicePathByName(mount_point, &dev_path)) {
        LERROR << "Couldn't get verity device path!";
        return false;
    }

    // Marks the underlying block device as read-only.
    fs_mgr_set_blk_ro(fstab_entry->blk_device);

    // Updates fstab_rec->blk_device to verity device name.
    free(fstab_entry->blk_device);
    fstab_entry->blk_device = strdup(dev_path.c_str());

    // Makes sure we've set everything up properly.
    if (wait_for_verity_dev && !fs_mgr_wait_for_file(dev_path, 1s)) {
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

FsManagerAvbUniquePtr FsManagerAvbHandle::Open(const fstab& fstab) {
    FsManagerAvbOps avb_ops(fstab);
    return DoOpen(&avb_ops);
}

FsManagerAvbUniquePtr FsManagerAvbHandle::Open(ByNameSymlinkMap&& by_name_symlink_map) {
    if (by_name_symlink_map.empty()) {
        LERROR << "Empty by_name_symlink_map when opening FsManagerAvbHandle";
        return nullptr;
    }
    FsManagerAvbOps avb_ops(std::move(by_name_symlink_map));
    return DoOpen(&avb_ops);
}

FsManagerAvbUniquePtr FsManagerAvbHandle::DoOpen(FsManagerAvbOps* avb_ops) {
    bool is_device_unlocked = fs_mgr_is_device_unlocked();

    FsManagerAvbUniquePtr avb_handle(new FsManagerAvbHandle());
    if (!avb_handle) {
        LERROR << "Failed to allocate FsManagerAvbHandle";
        return nullptr;
    }

    AvbSlotVerifyFlags flags = is_device_unlocked ? AVB_SLOT_VERIFY_FLAGS_ALLOW_VERIFICATION_ERROR
                                                  : AVB_SLOT_VERIFY_FLAGS_NONE;
    AvbSlotVerifyResult verify_result =
        avb_ops->AvbSlotVerify(fs_mgr_get_slot_suffix(), flags, &avb_handle->avb_slot_data_);

    // Only allow two verify results:
    //   - AVB_SLOT_VERIFY_RESULT_OK.
    //   - AVB_SLOT_VERIFY_RESULT_ERROR_VERIFICATION (for UNLOCKED state).
    //     If the device is UNLOCKED, i.e., |allow_verification_error| is true for
    //     AvbSlotVerify(), then the following return values are all non-fatal:
    //       * AVB_SLOT_VERIFY_RESULT_ERROR_VERIFICATION
    //       * AVB_SLOT_VERIFY_RESULT_ERROR_PUBLIC_KEY_REJECTED
    //       * AVB_SLOT_VERIFY_RESULT_ERROR_ROLLBACK_INDEX
    //     The latter two results were checked by bootloader prior to start fs_mgr so
    //     we just need to handle the first result here. See *dummy* operations in
    //     FsManagerAvbOps and the comments in external/avb/libavb/avb_slot_verify.h
    //     for more details.
    switch (verify_result) {
        case AVB_SLOT_VERIFY_RESULT_OK:
            avb_handle->status_ = kAvbHandleSuccess;
            break;
        case AVB_SLOT_VERIFY_RESULT_ERROR_VERIFICATION:
            if (!is_device_unlocked) {
                LERROR << "ERROR_VERIFICATION isn't allowed when the device is LOCKED";
                return nullptr;
            }
            avb_handle->status_ = kAvbHandleVerificationError;
            break;
        default:
            LERROR << "avb_slot_verify failed, result: " << verify_result;
            return nullptr;
    }

    // Sets the MAJOR.MINOR for init to set it into "ro.boot.avb_version".
    avb_handle->avb_version_ =
        android::base::StringPrintf("%d.%d", AVB_VERSION_MAJOR, AVB_VERSION_MINOR);

    // Checks whether FLAGS_VERIFICATION_DISABLED is set:
    //   - Only the top-level vbmeta struct is read.
    //   - vbmeta struct in other partitions are NOT processed, including AVB HASH descriptor(s)
    //     and AVB HASHTREE descriptor(s).
    AvbVBMetaImageHeader vbmeta_header;
    avb_vbmeta_image_header_to_host_byte_order(
        (AvbVBMetaImageHeader*)avb_handle->avb_slot_data_->vbmeta_images[0].vbmeta_data,
        &vbmeta_header);
    bool verification_disabled =
        ((AvbVBMetaImageFlags)vbmeta_header.flags & AVB_VBMETA_IMAGE_FLAGS_VERIFICATION_DISABLED);

    if (verification_disabled) {
        avb_handle->status_ = kAvbHandleVerificationDisabled;
    } else {
        // Verifies vbmeta structs against the digest passed from bootloader in kernel cmdline.
        std::unique_ptr<FsManagerAvbVerifier> avb_verifier = FsManagerAvbVerifier::Create();
        if (!avb_verifier) {
            LERROR << "Failed to create FsManagerAvbVerifier";
            return nullptr;
        }
        if (!avb_verifier->VerifyVbmetaImages(*avb_handle->avb_slot_data_)) {
            LERROR << "VerifyVbmetaImages failed";
            return nullptr;
        }

        // Checks whether FLAGS_HASHTREE_DISABLED is set.
        bool hashtree_disabled =
            ((AvbVBMetaImageFlags)vbmeta_header.flags & AVB_VBMETA_IMAGE_FLAGS_HASHTREE_DISABLED);
        if (hashtree_disabled) {
            avb_handle->status_ = kAvbHandleHashtreeDisabled;
        }
    }

    LINFO << "Returning avb_handle with status: " << avb_handle->status_;
    return avb_handle;
}

SetUpAvbHashtreeResult FsManagerAvbHandle::SetUpAvbHashtree(struct fstab_rec* fstab_entry,
                                                            bool wait_for_verity_dev) {
    if (!fstab_entry || status_ == kAvbHandleUninitialized || !avb_slot_data_ ||
        avb_slot_data_->num_vbmeta_images < 1) {
        return SetUpAvbHashtreeResult::kFail;
    }

    if (status_ == kAvbHandleHashtreeDisabled || status_ == kAvbHandleVerificationDisabled) {
        LINFO << "AVB HASHTREE disabled on: " << fstab_entry->mount_point;
        return SetUpAvbHashtreeResult::kDisabled;
    }

    // Derives partition_name from blk_device to query the corresponding AVB HASHTREE descriptor
    // to setup dm-verity. The partition_names in AVB descriptors are without A/B suffix.
    std::string partition_name;
    if (fstab_entry->fs_mgr_flags & MF_LOGICAL) {
        partition_name = fstab_entry->logical_partition_name;
    } else {
        partition_name = basename(fstab_entry->blk_device);
    }

    if (fstab_entry->fs_mgr_flags & MF_SLOTSELECT) {
        auto ab_suffix = partition_name.rfind(fs_mgr_get_slot_suffix());
        if (ab_suffix != std::string::npos) {
            partition_name.erase(ab_suffix);
        }
    }

    AvbHashtreeDescriptor hashtree_descriptor;
    std::string salt;
    std::string root_digest;
    if (!get_hashtree_descriptor(partition_name, *avb_slot_data_, &hashtree_descriptor, &salt,
                                 &root_digest)) {
        return SetUpAvbHashtreeResult::kFail;
    }

    // Converts HASHTREE descriptor to verity_table_params.
    if (!hashtree_dm_verity_setup(fstab_entry, hashtree_descriptor, salt, root_digest,
                                  wait_for_verity_dev)) {
        return SetUpAvbHashtreeResult::kFail;
    }

    return SetUpAvbHashtreeResult::kSuccess;
}

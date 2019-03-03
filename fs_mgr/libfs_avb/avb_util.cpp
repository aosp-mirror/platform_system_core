/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include "avb_util.h"

#include <unistd.h>

#include <array>
#include <sstream>

#include <android-base/file.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>

#include "util.h"

using android::base::Basename;
using android::base::ReadFileToString;
using android::base::StartsWith;
using android::base::unique_fd;

namespace android {
namespace fs_mgr {

std::string GetAvbPropertyDescriptor(const std::string& key,
                                     const std::vector<VBMetaData>& vbmeta_images) {
    size_t value_size;
    for (const auto& vbmeta : vbmeta_images) {
        const char* value = avb_property_lookup(vbmeta.data(), vbmeta.size(), key.data(),
                                                key.size(), &value_size);
        if (value != nullptr) {
            return {value, value_size};
        }
    }
    return "";
}

// Constructs dm-verity arguments for sending DM_TABLE_LOAD ioctl to kernel.
// See the following link for more details:
// https://gitlab.com/cryptsetup/cryptsetup/wikis/DMVerity
bool ConstructVerityTable(const FsAvbHashtreeDescriptor& hashtree_desc,
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

    android::dm::DmTargetVerity target(
            0, hashtree_desc.image_size / 512, hashtree_desc.dm_verity_version, blk_device,
            blk_device, hashtree_desc.data_block_size, hashtree_desc.hash_block_size,
            hashtree_desc.image_size / hashtree_desc.data_block_size,
            hashtree_desc.tree_offset / hashtree_desc.hash_block_size, hash_algorithm.str(),
            hashtree_desc.root_digest, hashtree_desc.salt);
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

bool HashtreeDmVeritySetup(FstabEntry* fstab_entry, const FsAvbHashtreeDescriptor& hashtree_desc,
                           bool wait_for_verity_dev) {
    android::dm::DmTable table;
    if (!ConstructVerityTable(hashtree_desc, fstab_entry->blk_device, &table) || !table.valid()) {
        LERROR << "Failed to construct verity table.";
        return false;
    }
    table.set_readonly(true);

    const std::string mount_point(Basename(fstab_entry->mount_point));
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
    SetBlockDeviceReadOnly(fstab_entry->blk_device);

    // Updates fstab_rec->blk_device to verity device name.
    fstab_entry->blk_device = dev_path;

    // Makes sure we've set everything up properly.
    if (wait_for_verity_dev && !WaitForFile(dev_path, 1s)) {
        return false;
    }

    return true;
}

std::unique_ptr<FsAvbHashtreeDescriptor> GetHashtreeDescriptor(
        const std::string& partition_name, const std::vector<VBMetaData>& vbmeta_images) {
    bool found = false;
    const uint8_t* desc_partition_name;
    auto hashtree_desc = std::make_unique<FsAvbHashtreeDescriptor>();

    for (const auto& vbmeta : vbmeta_images) {
        size_t num_descriptors;
        std::unique_ptr<const AvbDescriptor* [], decltype(&avb_free)> descriptors(
                avb_descriptor_get_all(vbmeta.data(), vbmeta.size(), &num_descriptors), avb_free);

        if (!descriptors || num_descriptors < 1) {
            continue;
        }

        for (size_t n = 0; n < num_descriptors && !found; n++) {
            AvbDescriptor desc;
            if (!avb_descriptor_validate_and_byteswap(descriptors[n], &desc)) {
                LWARNING << "Descriptor[" << n << "] is invalid";
                continue;
            }
            if (desc.tag == AVB_DESCRIPTOR_TAG_HASHTREE) {
                desc_partition_name =
                        (const uint8_t*)descriptors[n] + sizeof(AvbHashtreeDescriptor);
                if (!avb_hashtree_descriptor_validate_and_byteswap(
                        (AvbHashtreeDescriptor*)descriptors[n], hashtree_desc.get())) {
                    continue;
                }
                if (hashtree_desc->partition_name_len != partition_name.length()) {
                    continue;
                }
                // Notes that desc_partition_name is not NUL-terminated.
                std::string hashtree_partition_name((const char*)desc_partition_name,
                                                    hashtree_desc->partition_name_len);
                if (hashtree_partition_name == partition_name) {
                    found = true;
                }
            }
        }

        if (found) break;
    }

    if (!found) {
        LERROR << "Hashtree descriptor not found: " << partition_name;
        return nullptr;
    }

    hashtree_desc->partition_name = partition_name;

    const uint8_t* desc_salt = desc_partition_name + hashtree_desc->partition_name_len;
    hashtree_desc->salt = BytesToHex(desc_salt, hashtree_desc->salt_len);

    const uint8_t* desc_digest = desc_salt + hashtree_desc->salt_len;
    hashtree_desc->root_digest = BytesToHex(desc_digest, hashtree_desc->root_digest_len);

    return hashtree_desc;
}

bool LoadAvbHashtreeToEnableVerity(FstabEntry* fstab_entry, bool wait_for_verity_dev,
                                   const std::vector<VBMetaData>& vbmeta_images,
                                   const std::string& ab_suffix,
                                   const std::string& ab_other_suffix) {
    // Derives partition_name from blk_device to query the corresponding AVB HASHTREE descriptor
    // to setup dm-verity. The partition_names in AVB descriptors are without A/B suffix.
    std::string partition_name = DeriveAvbPartitionName(*fstab_entry, ab_suffix, ab_other_suffix);

    if (partition_name.empty()) {
        LERROR << "partition name is empty, cannot lookup AVB descriptors";
        return false;
    }

    std::unique_ptr<FsAvbHashtreeDescriptor> hashtree_descriptor =
            GetHashtreeDescriptor(partition_name, vbmeta_images);
    if (!hashtree_descriptor) {
        return false;
    }

    // Converts HASHTREE descriptor to verity table to load into kernel.
    // When success, the new device path will be returned, e.g., /dev/block/dm-2.
    return HashtreeDmVeritySetup(fstab_entry, *hashtree_descriptor, wait_for_verity_dev);
}

// Converts a AVB partition_name (without A/B suffix) to a device partition name.
// e.g.,       "system" => "system_a",
//       "system_other" => "system_b".
//
// If the device is non-A/B, converts it to a partition name without suffix.
// e.g.,       "system" => "system",
//       "system_other" => "system".
std::string AvbPartitionToDevicePatition(const std::string& avb_partition_name,
                                         const std::string& ab_suffix,
                                         const std::string& ab_other_suffix) {
    bool is_other_slot = false;
    std::string sanitized_partition_name(avb_partition_name);

    auto other_suffix = sanitized_partition_name.rfind("_other");
    if (other_suffix != std::string::npos) {
        sanitized_partition_name.erase(other_suffix);  // converts system_other => system
        is_other_slot = true;
    }

    auto append_suffix = is_other_slot ? ab_other_suffix : ab_suffix;
    return sanitized_partition_name + append_suffix;
}

// Converts fstab_entry.blk_device (with ab_suffix) to a AVB partition name.
// e.g., "/dev/block/by-name/system_a", slot_select       => "system",
//       "/dev/block/by-name/system_b", slot_select_other => "system_other".
//
// Or for a logical partition (with ab_suffix):
// e.g., "system_a", slot_select       => "system",
//       "system_b", slot_select_other => "system_other".
std::string DeriveAvbPartitionName(const FstabEntry& fstab_entry, const std::string& ab_suffix,
                                   const std::string& ab_other_suffix) {
    std::string partition_name;
    if (fstab_entry.fs_mgr_flags.logical) {
        partition_name = fstab_entry.logical_partition_name;
    } else {
        partition_name = Basename(fstab_entry.blk_device);
    }

    if (fstab_entry.fs_mgr_flags.slot_select) {
        auto found = partition_name.rfind(ab_suffix);
        if (found != std::string::npos) {
            partition_name.erase(found);  // converts system_a => system
        }
    } else if (fstab_entry.fs_mgr_flags.slot_select_other) {
        auto found = partition_name.rfind(ab_other_suffix);
        if (found != std::string::npos) {
            partition_name.erase(found);  // converts system_b => system
        }
        partition_name += "_other";  // converts system => system_other
    }

    return partition_name;
}

off64_t GetTotalSize(int fd) {
    off64_t saved_current = lseek64(fd, 0, SEEK_CUR);
    if (saved_current == -1) {
        PERROR << "Failed to get current position";
        return -1;
    }

    // lseek64() returns the resulting offset location from the beginning of the file.
    off64_t total_size = lseek64(fd, 0, SEEK_END);
    if (total_size == -1) {
        PERROR << "Failed to lseek64 to end of the partition";
        return -1;
    }

    // Restores the original offset.
    if (lseek64(fd, saved_current, SEEK_SET) == -1) {
        PERROR << "Failed to lseek64 to the original offset: " << saved_current;
    }

    return total_size;
}

std::unique_ptr<AvbFooter> GetAvbFooter(int fd) {
    std::array<uint8_t, AVB_FOOTER_SIZE> footer_buf;
    auto footer = std::make_unique<AvbFooter>();

    off64_t footer_offset = GetTotalSize(fd) - AVB_FOOTER_SIZE;

    ssize_t num_read =
            TEMP_FAILURE_RETRY(pread64(fd, footer_buf.data(), AVB_FOOTER_SIZE, footer_offset));
    if (num_read < 0 || num_read != AVB_FOOTER_SIZE) {
        PERROR << "Failed to read AVB footer at offset: " << footer_offset;
        return nullptr;
    }

    if (!avb_footer_validate_and_byteswap((const AvbFooter*)footer_buf.data(), footer.get())) {
        PERROR << "AVB footer verification failed at offset " << footer_offset;
        return nullptr;
    }

    return footer;
}

bool ValidatePublicKeyBlob(const uint8_t* key, size_t length,
                           const std::string& expected_key_blob) {
    if (expected_key_blob.empty()) {  // no expectation of the key, return true.
        return true;
    }
    if (expected_key_blob.size() != length) {
        return false;
    }
    if (0 == memcmp(key, expected_key_blob.data(), length)) {
        return true;
    }
    return false;
}

bool ValidatePublicKeyBlob(const std::string& key_blob_to_validate,
                           const std::vector<std::string>& allowed_key_paths) {
    std::string allowed_key_blob;
    if (key_blob_to_validate.empty()) {
        LWARNING << "Failed to validate an empty key";
        return false;
    }
    for (const auto& path : allowed_key_paths) {
        if (ReadFileToString(path, &allowed_key_blob)) {
            if (key_blob_to_validate == allowed_key_blob) return true;
        }
    }
    return false;
}

VBMetaVerifyResult VerifyVBMetaSignature(const VBMetaData& vbmeta,
                                         const std::string& expected_public_key_blob,
                                         std::string* out_public_key_data) {
    const uint8_t* pk_data;
    size_t pk_len;
    ::AvbVBMetaVerifyResult vbmeta_ret;

    vbmeta_ret = avb_vbmeta_image_verify(vbmeta.data(), vbmeta.size(), &pk_data, &pk_len);

    if (out_public_key_data != nullptr) {
        out_public_key_data->clear();
        if (pk_len > 0) {
            out_public_key_data->append(reinterpret_cast<const char*>(pk_data), pk_len);
        }
    }

    switch (vbmeta_ret) {
        case AVB_VBMETA_VERIFY_RESULT_OK:
            if (pk_data == nullptr || pk_len <= 0) {
                LERROR << vbmeta.partition()
                       << ": Error verifying vbmeta image: failed to get public key";
                return VBMetaVerifyResult::kError;
            }
            if (!ValidatePublicKeyBlob(pk_data, pk_len, expected_public_key_blob)) {
                LERROR << vbmeta.partition() << ": Error verifying vbmeta image: public key used to"
                       << " sign data does not match key in chain descriptor";
                return VBMetaVerifyResult::kErrorVerification;
            }
            return VBMetaVerifyResult::kSuccess;
        case AVB_VBMETA_VERIFY_RESULT_OK_NOT_SIGNED:
        case AVB_VBMETA_VERIFY_RESULT_HASH_MISMATCH:
        case AVB_VBMETA_VERIFY_RESULT_SIGNATURE_MISMATCH:
            LERROR << vbmeta.partition() << ": Error verifying vbmeta image: "
                   << avb_vbmeta_verify_result_to_string(vbmeta_ret);
            return VBMetaVerifyResult::kErrorVerification;
        case AVB_VBMETA_VERIFY_RESULT_INVALID_VBMETA_HEADER:
            // No way to continue this case.
            LERROR << vbmeta.partition() << ": Error verifying vbmeta image: invalid vbmeta header";
            break;
        case AVB_VBMETA_VERIFY_RESULT_UNSUPPORTED_VERSION:
            // No way to continue this case.
            LERROR << vbmeta.partition()
                   << ": Error verifying vbmeta image: unsupported AVB version";
            break;
        default:
            LERROR << "Unknown vbmeta image verify return value: " << vbmeta_ret;
            break;
    }

    return VBMetaVerifyResult::kError;
}

std::unique_ptr<VBMetaData> VerifyVBMetaData(int fd, const std::string& partition_name,
                                             const std::string& expected_public_key_blob,
                                             std::string* out_public_key_data,
                                             VBMetaVerifyResult* out_verify_result) {
    uint64_t vbmeta_offset = 0;
    uint64_t vbmeta_size = VBMetaData::kMaxVBMetaSize;
    bool is_vbmeta_partition = StartsWith(partition_name, "vbmeta");

    if (out_verify_result) {
        *out_verify_result = VBMetaVerifyResult::kError;
    }

    if (!is_vbmeta_partition) {
        std::unique_ptr<AvbFooter> footer = GetAvbFooter(fd);
        if (!footer) {
            return nullptr;
        }
        vbmeta_offset = footer->vbmeta_offset;
        vbmeta_size = footer->vbmeta_size;
    }

    if (vbmeta_size > VBMetaData::kMaxVBMetaSize) {
        LERROR << "VbMeta size in footer exceeds kMaxVBMetaSize";
        return nullptr;
    }

    auto vbmeta = std::make_unique<VBMetaData>(vbmeta_size, partition_name);
    ssize_t num_read = TEMP_FAILURE_RETRY(pread64(fd, vbmeta->data(), vbmeta_size, vbmeta_offset));
    // Allows partial read for vbmeta partition, because its vbmeta_size is kMaxVBMetaSize.
    if (num_read < 0 || (!is_vbmeta_partition && static_cast<uint64_t>(num_read) != vbmeta_size)) {
        PERROR << partition_name << ": Failed to read vbmeta at offset " << vbmeta_offset
               << " with size " << vbmeta_size;
        return nullptr;
    }

    auto verify_result =
            VerifyVBMetaSignature(*vbmeta, expected_public_key_blob, out_public_key_data);

    if (out_verify_result != nullptr) {
        *out_verify_result = verify_result;
    }

    if (verify_result == VBMetaVerifyResult::kSuccess ||
        verify_result == VBMetaVerifyResult::kErrorVerification) {
        return vbmeta;
    }

    return nullptr;
}

bool RollbackDetected(const std::string& partition_name ATTRIBUTE_UNUSED,
                      uint64_t rollback_index ATTRIBUTE_UNUSED) {
    // TODO(bowgotsai): Support rollback protection.
    return false;
}

std::vector<ChainInfo> GetChainPartitionInfo(const VBMetaData& vbmeta, bool* fatal_error) {
    CHECK(fatal_error != nullptr);
    std::vector<ChainInfo> chain_partitions;

    size_t num_descriptors;
    std::unique_ptr<const AvbDescriptor* [], decltype(&avb_free)> descriptors(
            avb_descriptor_get_all(vbmeta.data(), vbmeta.size(), &num_descriptors), avb_free);

    if (!descriptors || num_descriptors < 1) {
        return {};
    }

    for (size_t i = 0; i < num_descriptors; i++) {
        AvbDescriptor desc;
        if (!avb_descriptor_validate_and_byteswap(descriptors[i], &desc)) {
            LERROR << "Descriptor[" << i << "] is invalid in vbmeta: " << vbmeta.partition();
            *fatal_error = true;
            return {};
        }
        if (desc.tag == AVB_DESCRIPTOR_TAG_CHAIN_PARTITION) {
            AvbChainPartitionDescriptor chain_desc;
            if (!avb_chain_partition_descriptor_validate_and_byteswap(
                        (AvbChainPartitionDescriptor*)descriptors[i], &chain_desc)) {
                LERROR << "Chain descriptor[" << i
                       << "] is invalid in vbmeta: " << vbmeta.partition();
                *fatal_error = true;
                return {};
            }
            const char* chain_partition_name =
                    ((const char*)descriptors[i]) + sizeof(AvbChainPartitionDescriptor);
            const char* chain_public_key_blob =
                    chain_partition_name + chain_desc.partition_name_len;
            chain_partitions.emplace_back(
                    std::string(chain_partition_name, chain_desc.partition_name_len),
                    std::string(chain_public_key_blob, chain_desc.public_key_len));
        }
    }

    return chain_partitions;
}

// Loads the vbmeta from a given path.
std::unique_ptr<VBMetaData> LoadAndVerifyVbmetaByPath(
        const std::string& image_path, const std::string& partition_name,
        const std::string& expected_public_key_blob, bool allow_verification_error,
        bool rollback_protection, bool is_chained_vbmeta, std::string* out_public_key_data,
        bool* out_verification_disabled, VBMetaVerifyResult* out_verify_result) {
    if (out_verify_result) {
        *out_verify_result = VBMetaVerifyResult::kError;
    }

    // Ensures the device path (might be a symlink created by init) is ready to access.
    if (!WaitForFile(image_path, 1s)) {
        PERROR << "No such path: " << image_path;
        return nullptr;
    }

    unique_fd fd(TEMP_FAILURE_RETRY(open(image_path.c_str(), O_RDONLY | O_CLOEXEC)));
    if (fd < 0) {
        PERROR << "Failed to open: " << image_path;
        return nullptr;
    }

    VBMetaVerifyResult verify_result;
    std::unique_ptr<VBMetaData> vbmeta = VerifyVBMetaData(
            fd, partition_name, expected_public_key_blob, out_public_key_data, &verify_result);
    if (!vbmeta) {
        LERROR << partition_name << ": Failed to load vbmeta, result: " << verify_result;
        return nullptr;
    }
    vbmeta->set_vbmeta_path(image_path);

    if (!allow_verification_error && verify_result == VBMetaVerifyResult::kErrorVerification) {
        LERROR << partition_name << ": allow verification error is not allowed";
        return nullptr;
    }

    std::unique_ptr<AvbVBMetaImageHeader> vbmeta_header =
            vbmeta->GetVBMetaHeader(true /* update_vbmeta_size */);
    if (!vbmeta_header) {
        LERROR << partition_name << ": Failed to get vbmeta header";
        return nullptr;
    }

    if (rollback_protection && RollbackDetected(partition_name, vbmeta_header->rollback_index)) {
        return nullptr;
    }

    // vbmeta flags can only be set by the top-level vbmeta image.
    if (is_chained_vbmeta && vbmeta_header->flags != 0) {
        LERROR << partition_name << ": chained vbmeta image has non-zero flags";
        return nullptr;
    }

    // Checks if verification has been disabled by setting a bit in the image.
    if (out_verification_disabled) {
        if (vbmeta_header->flags & AVB_VBMETA_IMAGE_FLAGS_VERIFICATION_DISABLED) {
            LWARNING << "VERIFICATION_DISABLED bit is set for partition: " << partition_name;
            *out_verification_disabled = true;
        } else {
            *out_verification_disabled = false;
        }
    }

    if (out_verify_result) {
        *out_verify_result = verify_result;
    }

    return vbmeta;
}

VBMetaVerifyResult LoadAndVerifyVbmetaByPartition(
    const std::string& partition_name, const std::string& ab_suffix,
    const std::string& ab_other_suffix, const std::string& expected_public_key_blob,
    bool allow_verification_error, bool load_chained_vbmeta, bool rollback_protection,
    std::function<std::string(const std::string&)> device_path_constructor, bool is_chained_vbmeta,
    std::vector<VBMetaData>* out_vbmeta_images) {
    auto image_path = device_path_constructor(
        AvbPartitionToDevicePatition(partition_name, ab_suffix, ab_other_suffix));

    bool verification_disabled = false;
    VBMetaVerifyResult verify_result;
    auto vbmeta = LoadAndVerifyVbmetaByPath(image_path, partition_name, expected_public_key_blob,
                                            allow_verification_error, rollback_protection,
                                            is_chained_vbmeta, nullptr /* out_public_key_data */,
                                            &verification_disabled, &verify_result);

    if (!vbmeta) {
        return VBMetaVerifyResult::kError;
    }
    if (out_vbmeta_images) {
        out_vbmeta_images->emplace_back(std::move(*vbmeta));
    }

    // Only loads chained vbmeta if AVB verification is NOT disabled.
    if (!verification_disabled && load_chained_vbmeta) {
        bool fatal_error = false;
        auto chain_partitions = GetChainPartitionInfo(*out_vbmeta_images->rbegin(), &fatal_error);
        if (fatal_error) {
            return VBMetaVerifyResult::kError;
        }
        for (auto& chain : chain_partitions) {
            auto sub_ret = LoadAndVerifyVbmetaByPartition(
                chain.partition_name, ab_suffix, ab_other_suffix, chain.public_key_blob,
                allow_verification_error, load_chained_vbmeta, rollback_protection,
                device_path_constructor, true, /* is_chained_vbmeta */
                out_vbmeta_images);
            if (sub_ret != VBMetaVerifyResult::kSuccess) {
                verify_result = sub_ret;  // might be 'ERROR' or 'ERROR VERIFICATION'.
                if (verify_result == VBMetaVerifyResult::kError) {
                    return verify_result;  // stop here if we got an 'ERROR'.
                }
            }
        }
    }

    return verify_result;
}

}  // namespace fs_mgr
}  // namespace android

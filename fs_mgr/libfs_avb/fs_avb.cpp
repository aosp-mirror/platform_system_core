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

#include "fs_avb/fs_avb.h"

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
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <libavb/libavb.h>
#include <libdm/dm.h>

#include "avb_ops.h"
#include "avb_util.h"
#include "sha.h"
#include "util.h"

using android::base::Basename;
using android::base::ParseUint;
using android::base::ReadFileToString;
using android::base::Split;
using android::base::StringPrintf;

namespace android {
namespace fs_mgr {

template <typename Hasher>
std::pair<size_t, bool> VerifyVbmetaDigest(const std::vector<VBMetaData>& vbmeta_images,
                                           const uint8_t* expected_digest) {
    size_t total_size = 0;
    Hasher hasher;
    for (const auto& vbmeta : vbmeta_images) {
        hasher.update(vbmeta.data(), vbmeta.size());
        total_size += vbmeta.size();
    }

    bool matched = (memcmp(hasher.finalize(), expected_digest, Hasher::DIGEST_SIZE) == 0);

    return std::make_pair(total_size, matched);
}

template <typename Hasher>
std::pair<std::string, size_t> CalculateVbmetaDigest(const std::vector<VBMetaData>& vbmeta_images) {
    std::string digest;
    size_t total_size = 0;

    Hasher hasher;
    for (const auto& vbmeta : vbmeta_images) {
        hasher.update(vbmeta.data(), vbmeta.size());
        total_size += vbmeta.size();
    }

    // Converts digest bytes to a hex string.
    digest = BytesToHex(hasher.finalize(), Hasher::DIGEST_SIZE);
    return std::make_pair(digest, total_size);
}

// class AvbVerifier
// -----------------
// Reads the following values from kernel cmdline and provides the
// VerifyVbmetaImages() to verify AvbSlotVerifyData.
//   - androidboot.vbmeta.hash_alg
//   - androidboot.vbmeta.size
//   - androidboot.vbmeta.digest
class AvbVerifier {
  public:
    // The factory method to return a unique_ptr<AvbVerifier>
    static std::unique_ptr<AvbVerifier> Create();
    bool VerifyVbmetaImages(const std::vector<VBMetaData>& vbmeta_images);

  protected:
    AvbVerifier() = default;

  private:
    HashAlgorithm hash_alg_;
    uint8_t digest_[SHA512_DIGEST_LENGTH];
    size_t vbmeta_size_;
};

std::unique_ptr<AvbVerifier> AvbVerifier::Create() {
    std::unique_ptr<AvbVerifier> avb_verifier(new AvbVerifier());
    if (!avb_verifier) {
        LERROR << "Failed to create unique_ptr<AvbVerifier>";
        return nullptr;
    }

    std::string value;
    if (!fs_mgr_get_boot_config("vbmeta.size", &value) ||
        !ParseUint(value.c_str(), &avb_verifier->vbmeta_size_)) {
        LERROR << "Invalid hash size: " << value.c_str();
        return nullptr;
    }

    // Reads hash algorithm.
    size_t expected_digest_size = 0;
    std::string hash_alg;
    fs_mgr_get_boot_config("vbmeta.hash_alg", &hash_alg);
    if (hash_alg == "sha256") {
        expected_digest_size = SHA256_DIGEST_LENGTH * 2;
        avb_verifier->hash_alg_ = HashAlgorithm::kSHA256;
    } else if (hash_alg == "sha512") {
        expected_digest_size = SHA512_DIGEST_LENGTH * 2;
        avb_verifier->hash_alg_ = HashAlgorithm::kSHA512;
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

    if (!HexToBytes(avb_verifier->digest_, sizeof(avb_verifier->digest_), digest)) {
        LERROR << "Hash digest contains non-hexidecimal character: " << digest.c_str();
        return nullptr;
    }

    return avb_verifier;
}

bool AvbVerifier::VerifyVbmetaImages(const std::vector<VBMetaData>& vbmeta_images) {
    if (vbmeta_images.empty()) {
        LERROR << "No vbmeta images";
        return false;
    }

    size_t total_size = 0;
    bool digest_matched = false;

    if (hash_alg_ == HashAlgorithm::kSHA256) {
        std::tie(total_size, digest_matched) =
                VerifyVbmetaDigest<SHA256Hasher>(vbmeta_images, digest_);
    } else if (hash_alg_ == HashAlgorithm::kSHA512) {
        std::tie(total_size, digest_matched) =
                VerifyVbmetaDigest<SHA512Hasher>(vbmeta_images, digest_);
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

// class AvbHandle
// ---------------
AvbUniquePtr AvbHandle::LoadAndVerifyVbmeta(
        const std::string& partition_name, const std::string& ab_suffix,
        const std::string& ab_other_suffix, const std::string& expected_public_key_path,
        const HashAlgorithm& hash_algorithm, bool allow_verification_error,
        bool load_chained_vbmeta, bool rollback_protection,
        std::function<std::string(const std::string&)> custom_device_path) {
    AvbUniquePtr avb_handle(new AvbHandle());
    if (!avb_handle) {
        LERROR << "Failed to allocate AvbHandle";
        return nullptr;
    }

    std::string expected_key_blob;
    if (!expected_public_key_path.empty()) {
        if (access(expected_public_key_path.c_str(), F_OK) != 0) {
            LERROR << "Expected public key path doesn't exist: " << expected_public_key_path;
            return nullptr;
        } else if (!ReadFileToString(expected_public_key_path, &expected_key_blob)) {
            LERROR << "Failed to load: " << expected_public_key_path;
            return nullptr;
        }
    }

    auto android_by_name_symlink = [](const std::string& partition_name_with_ab) {
        return "/dev/block/by-name/" + partition_name_with_ab;
    };

    auto device_path = custom_device_path ? custom_device_path : android_by_name_symlink;

    auto verify_result = LoadAndVerifyVbmetaByPartition(
        partition_name, ab_suffix, ab_other_suffix, expected_key_blob, allow_verification_error,
        load_chained_vbmeta, rollback_protection, device_path, false,
        /* is_chained_vbmeta */ &avb_handle->vbmeta_images_);
    switch (verify_result) {
        case VBMetaVerifyResult::kSuccess:
            avb_handle->status_ = AvbHandleStatus::kSuccess;
            break;
        case VBMetaVerifyResult::kErrorVerification:
            avb_handle->status_ = AvbHandleStatus::kVerificationError;
            break;
        default:
            LERROR << "LoadAndVerifyVbmetaByPartition failed, result: " << verify_result;
            return nullptr;
    }

    // Sanity check here because we have to use vbmeta_images_[0] below.
    if (avb_handle->vbmeta_images_.size() < 1) {
        LERROR << "LoadAndVerifyVbmetaByPartition failed, no vbmeta loaded";
        return nullptr;
    }

    // Sets the MAJOR.MINOR for init to set it into "ro.boot.avb_version".
    avb_handle->avb_version_ = StringPrintf("%d.%d", AVB_VERSION_MAJOR, AVB_VERSION_MINOR);

    // Checks any disabled flag is set.
    std::unique_ptr<AvbVBMetaImageHeader> vbmeta_header =
            avb_handle->vbmeta_images_[0].GetVBMetaHeader();
    bool verification_disabled = ((AvbVBMetaImageFlags)vbmeta_header->flags &
                                  AVB_VBMETA_IMAGE_FLAGS_VERIFICATION_DISABLED);
    bool hashtree_disabled =
            ((AvbVBMetaImageFlags)vbmeta_header->flags & AVB_VBMETA_IMAGE_FLAGS_HASHTREE_DISABLED);
    if (verification_disabled) {
        avb_handle->status_ = AvbHandleStatus::kVerificationDisabled;
    } else if (hashtree_disabled) {
        avb_handle->status_ = AvbHandleStatus::kHashtreeDisabled;
    }

    // Calculates the summary info for all vbmeta_images_;
    std::string digest;
    size_t total_size;
    if (hash_algorithm == HashAlgorithm::kSHA256) {
        std::tie(digest, total_size) =
                CalculateVbmetaDigest<SHA256Hasher>(avb_handle->vbmeta_images_);
    } else if (hash_algorithm == HashAlgorithm::kSHA512) {
        std::tie(digest, total_size) =
                CalculateVbmetaDigest<SHA512Hasher>(avb_handle->vbmeta_images_);
    } else {
        LERROR << "Invalid hash algorithm";
        return nullptr;
    }
    avb_handle->vbmeta_info_ = VBMetaInfo(digest, hash_algorithm, total_size);

    LINFO << "Returning avb_handle with status: " << avb_handle->status_;
    return avb_handle;
}

AvbUniquePtr AvbHandle::LoadAndVerifyVbmeta(const FstabEntry& fstab_entry) {
    if (fstab_entry.avb_keys.empty()) {
        LERROR << "avb_keys=/path/to/key(s) is missing for " << fstab_entry.mount_point;
        return nullptr;
    }

    // Binds allow_verification_error and rollback_protection to device unlock state.
    bool allow_verification_error = IsDeviceUnlocked();
    bool rollback_protection = !allow_verification_error;

    std::string public_key_data;
    bool verification_disabled = false;
    VBMetaVerifyResult verify_result = VBMetaVerifyResult::kError;
    std::unique_ptr<VBMetaData> vbmeta = LoadAndVerifyVbmetaByPath(
            fstab_entry.blk_device, "" /* partition_name, no need for a standalone path */,
            "" /* expected_public_key_blob, */, allow_verification_error, rollback_protection,
            false /* not is_chained_vbmeta */, &public_key_data, &verification_disabled,
            &verify_result);

    if (!vbmeta) {
        LERROR << "Failed to load vbmeta: " << fstab_entry.blk_device;
        return nullptr;
    }

    AvbUniquePtr avb_handle(new AvbHandle());
    if (!avb_handle) {
        LERROR << "Failed to allocate AvbHandle";
        return nullptr;
    }
    avb_handle->vbmeta_images_.emplace_back(std::move(*vbmeta));

    switch (verify_result) {
        case VBMetaVerifyResult::kSuccess:
            avb_handle->status_ = AvbHandleStatus::kSuccess;
            break;
        case VBMetaVerifyResult::kErrorVerification:
            avb_handle->status_ = AvbHandleStatus::kVerificationError;
            break;
        default:
            LERROR << "LoadAndVerifyVbmetaByPath failed, result: " << verify_result;
            return nullptr;
    }

    if (!ValidatePublicKeyBlob(public_key_data, Split(fstab_entry.avb_keys, ":"))) {
        avb_handle->status_ = AvbHandleStatus::kVerificationError;
        LWARNING << "Found unknown public key used to sign " << fstab_entry.mount_point;
        if (!allow_verification_error) {
            LERROR << "Unknown public key is not allowed";
            return nullptr;
        }
    }

    if (verification_disabled) {
        LINFO << "AVB verification disabled on: " << fstab_entry.mount_point;
        avb_handle->status_ = AvbHandleStatus::kVerificationDisabled;
    }

    LINFO << "Returning avb_handle for '" << fstab_entry.mount_point
          << "' with status: " << avb_handle->status_;
    return avb_handle;
}

AvbUniquePtr AvbHandle::LoadAndVerifyVbmeta() {
    // Loads inline vbmeta images, starting from /vbmeta.
    return LoadAndVerifyVbmeta("vbmeta", fs_mgr_get_slot_suffix(), fs_mgr_get_other_slot_suffix(),
                               {} /* expected_public_key, already checked by bootloader */,
                               HashAlgorithm::kSHA256,
                               IsDeviceUnlocked(), /* allow_verification_error */
                               true,               /* load_chained_vbmeta */
                               false, /* rollback_protection, already checked by bootloader */
                               nullptr /* custom_device_path */);
}

AvbUniquePtr AvbHandle::Open() {
    bool is_device_unlocked = IsDeviceUnlocked();

    AvbUniquePtr avb_handle(new AvbHandle());
    if (!avb_handle) {
        LERROR << "Failed to allocate AvbHandle";
        return nullptr;
    }

    FsManagerAvbOps avb_ops;
    AvbSlotVerifyFlags flags = is_device_unlocked ? AVB_SLOT_VERIFY_FLAGS_ALLOW_VERIFICATION_ERROR
                                                  : AVB_SLOT_VERIFY_FLAGS_NONE;
    AvbSlotVerifyResult verify_result =
            avb_ops.AvbSlotVerify(fs_mgr_get_slot_suffix(), flags, &avb_handle->vbmeta_images_);

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
            avb_handle->status_ = AvbHandleStatus::kSuccess;
            break;
        case AVB_SLOT_VERIFY_RESULT_ERROR_VERIFICATION:
            if (!is_device_unlocked) {
                LERROR << "ERROR_VERIFICATION isn't allowed when the device is LOCKED";
                return nullptr;
            }
            avb_handle->status_ = AvbHandleStatus::kVerificationError;
            break;
        default:
            LERROR << "avb_slot_verify failed, result: " << verify_result;
            return nullptr;
    }

    // Sets the MAJOR.MINOR for init to set it into "ro.boot.avb_version".
    avb_handle->avb_version_ = StringPrintf("%d.%d", AVB_VERSION_MAJOR, AVB_VERSION_MINOR);

    // Checks whether FLAGS_VERIFICATION_DISABLED is set:
    //   - Only the top-level vbmeta struct is read.
    //   - vbmeta struct in other partitions are NOT processed, including AVB HASH descriptor(s)
    //     and AVB HASHTREE descriptor(s).
    AvbVBMetaImageHeader vbmeta_header;
    avb_vbmeta_image_header_to_host_byte_order(
            (AvbVBMetaImageHeader*)avb_handle->vbmeta_images_[0].data(), &vbmeta_header);
    bool verification_disabled = ((AvbVBMetaImageFlags)vbmeta_header.flags &
                                  AVB_VBMETA_IMAGE_FLAGS_VERIFICATION_DISABLED);

    if (verification_disabled) {
        avb_handle->status_ = AvbHandleStatus::kVerificationDisabled;
    } else {
        // Verifies vbmeta structs against the digest passed from bootloader in kernel cmdline.
        std::unique_ptr<AvbVerifier> avb_verifier = AvbVerifier::Create();
        if (!avb_verifier) {
            LERROR << "Failed to create AvbVerifier";
            return nullptr;
        }
        if (!avb_verifier->VerifyVbmetaImages(avb_handle->vbmeta_images_)) {
            LERROR << "VerifyVbmetaImages failed";
            return nullptr;
        }

        // Checks whether FLAGS_HASHTREE_DISABLED is set.
        bool hashtree_disabled = ((AvbVBMetaImageFlags)vbmeta_header.flags &
                                  AVB_VBMETA_IMAGE_FLAGS_HASHTREE_DISABLED);
        if (hashtree_disabled) {
            avb_handle->status_ = AvbHandleStatus::kHashtreeDisabled;
        }
    }

    LINFO << "Returning avb_handle with status: " << avb_handle->status_;
    return avb_handle;
}

AvbHashtreeResult AvbHandle::SetUpStandaloneAvbHashtree(FstabEntry* fstab_entry,
                                                        bool wait_for_verity_dev) {
    auto avb_handle = LoadAndVerifyVbmeta(*fstab_entry);
    if (!avb_handle) {
        return AvbHashtreeResult::kFail;
    }

    return avb_handle->SetUpAvbHashtree(fstab_entry, wait_for_verity_dev);
}

AvbHashtreeResult AvbHandle::SetUpAvbHashtree(FstabEntry* fstab_entry, bool wait_for_verity_dev) {
    if (!fstab_entry || status_ == AvbHandleStatus::kUninitialized || vbmeta_images_.size() < 1) {
        return AvbHashtreeResult::kFail;
    }

    if (status_ == AvbHandleStatus::kHashtreeDisabled ||
        status_ == AvbHandleStatus::kVerificationDisabled) {
        LINFO << "AVB HASHTREE disabled on: " << fstab_entry->mount_point;
        return AvbHashtreeResult::kDisabled;
    }

    if (!LoadAvbHashtreeToEnableVerity(fstab_entry, wait_for_verity_dev, vbmeta_images_,
                                       fs_mgr_get_slot_suffix(), fs_mgr_get_other_slot_suffix())) {
        return AvbHashtreeResult::kFail;
    }

    return AvbHashtreeResult::kSuccess;
}

std::string AvbHandle::GetSecurityPatchLevel(const FstabEntry& fstab_entry) const {
    if (vbmeta_images_.size() < 1) {
        return "";
    }
    std::string avb_partition_name = DeriveAvbPartitionName(fstab_entry, fs_mgr_get_slot_suffix(),
                                                            fs_mgr_get_other_slot_suffix());
    auto avb_prop_name = "com.android.build." + avb_partition_name + ".security_patch";
    return GetAvbPropertyDescriptor(avb_prop_name, vbmeta_images_);
}

bool AvbHandle::IsDeviceUnlocked() {
    return android::fs_mgr::IsDeviceUnlocked();
}

}  // namespace fs_mgr
}  // namespace android

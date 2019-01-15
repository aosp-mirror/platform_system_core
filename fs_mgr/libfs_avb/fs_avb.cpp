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
#include <libavb/libavb.h>
#include <libdm/dm.h>

#include "avb_ops.h"
#include "avb_util.h"
#include "sha.h"
#include "util.h"

using android::base::Basename;
using android::base::ParseUint;
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
    enum HashAlgorithm {
        kInvalid = 0,
        kSHA256 = 1,
        kSHA512 = 2,
    };

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

    if (hash_alg_ == kSHA256) {
        std::tie(total_size, digest_matched) =
                VerifyVbmetaDigest<SHA256Hasher>(vbmeta_images, digest_);
    } else if (hash_alg_ == kSHA512) {
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
        avb_handle->status_ = kAvbHandleVerificationDisabled;
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
            avb_handle->status_ = kAvbHandleHashtreeDisabled;
        }
    }

    LINFO << "Returning avb_handle with status: " << avb_handle->status_;
    return avb_handle;
}

AvbHashtreeResult AvbHandle::SetUpAvbHashtree(FstabEntry* fstab_entry, bool wait_for_verity_dev) {
    if (!fstab_entry || status_ == kAvbHandleUninitialized || vbmeta_images_.size() < 1) {
        return AvbHashtreeResult::kFail;
    }

    if (status_ == kAvbHandleHashtreeDisabled || status_ == kAvbHandleVerificationDisabled) {
        LINFO << "AVB HASHTREE disabled on: " << fstab_entry->mount_point;
        return AvbHashtreeResult::kDisabled;
    }

    // Derives partition_name from blk_device to query the corresponding AVB HASHTREE descriptor
    // to setup dm-verity. The partition_names in AVB descriptors are without A/B suffix.
    std::string partition_name;
    if (fstab_entry->fs_mgr_flags.logical) {
        partition_name = fstab_entry->logical_partition_name;
    } else {
        partition_name = Basename(fstab_entry->blk_device);
    }

    if (fstab_entry->fs_mgr_flags.slot_select) {
        auto ab_suffix = partition_name.rfind(fs_mgr_get_slot_suffix());
        if (ab_suffix != std::string::npos) {
            partition_name.erase(ab_suffix);
        }
    }

    AvbHashtreeDescriptor hashtree_descriptor;
    std::string salt;
    std::string root_digest;
    if (!GetHashtreeDescriptor(partition_name, vbmeta_images_, &hashtree_descriptor, &salt,
                               &root_digest)) {
        return AvbHashtreeResult::kFail;
    }

    // Converts HASHTREE descriptor to verity_table_params.
    if (!HashtreeDmVeritySetup(fstab_entry, hashtree_descriptor, salt, root_digest,
                               wait_for_verity_dev)) {
        return AvbHashtreeResult::kFail;
    }

    return AvbHashtreeResult::kSuccess;
}

}  // namespace fs_mgr
}  // namespace android

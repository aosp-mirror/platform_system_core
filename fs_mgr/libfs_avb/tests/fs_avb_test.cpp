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

#include <endian.h>
#include <stdlib.h>

#include <android-base/file.h>
#include <android-base/strings.h>
#include <base/files/file_util.h>
#include <fs_avb/fs_avb.h>
#include <libavb/libavb.h>

#include "fs_avb_test_util.h"

// Target classes or functions to test:
using android::fs_mgr::AvbHandle;
using android::fs_mgr::AvbHandleStatus;
using android::fs_mgr::HashAlgorithm;

namespace fs_avb_host_test {

class PublicFsAvbTest : public BaseFsAvbTest {
  public:
    PublicFsAvbTest(){};

  protected:
    ~PublicFsAvbTest(){};
    // Modifies |flags| field in the vbmeta header in an Avb image.
    // e.g., AVB_VBMETA_IMAGE_FLAGS_VERIFICATION_DISABLED.
    void ModifyVBMetaHeaderFlags(const base::FilePath& vbmeta_image_path, uint32_t flags);
};

void PublicFsAvbTest::ModifyVBMetaHeaderFlags(const base::FilePath& vbmeta_image_path,
                                              uint32_t flags) {
    if (!base::PathExists(vbmeta_image_path)) return;

    // Only support modifying the flags in vbmeta*.img.
    std::string image_file_name = vbmeta_image_path.RemoveExtension().BaseName().value();
    ASSERT_TRUE(android::base::StartsWithIgnoreCase(image_file_name, "vbmeta"));

    android::base::unique_fd fd(open(vbmeta_image_path.value().c_str(), O_RDWR | O_CLOEXEC));
    EXPECT_TRUE(fd > 0);

    auto flags_offset = offsetof(AvbVBMetaImageHeader, flags);
    uint32_t flags_data = htobe32(flags);
    EXPECT_EQ(flags_offset, lseek64(fd, flags_offset, SEEK_SET));
    EXPECT_EQ(sizeof flags_data, write(fd, &flags_data, sizeof flags_data));
}

TEST_F(PublicFsAvbTest, LoadAndVerifyVbmeta) {
    // Generates a raw boot.img
    const size_t boot_image_size = 5 * 1024 * 1024;
    const size_t boot_partition_size = 10 * 1024 * 1024;
    base::FilePath boot_path = GenerateImage("boot.img", boot_image_size);

    // Adds AVB Hash Footer.
    AddAvbFooter(boot_path, "hash", "boot", boot_partition_size, "SHA256_RSA2048", 10,
                 data_dir_.Append("testkey_rsa2048.pem"), "d00df00d",
                 "--internal_release_string \"unit test\"");

    // Generates a raw system.img, use a smaller size to speed-up unit test.
    const size_t system_image_size = 10 * 1024 * 1024;
    const size_t system_partition_size = 15 * 1024 * 1024;
    base::FilePath system_path = GenerateImage("system.img", system_image_size);
    // Adds AVB Hashtree Footer.
    AddAvbFooter(system_path, "hashtree", "system", system_partition_size, "SHA512_RSA4096", 20,
                 data_dir_.Append("testkey_rsa4096.pem"), "d00df00d",
                 "--internal_release_string \"unit test\"");

    // Generates chain partition descriptors.
    base::FilePath rsa2048_public_key =
            ExtractPublicKeyAvb(data_dir_.Append("testkey_rsa2048.pem"));
    base::FilePath rsa4096_public_key =
            ExtractPublicKeyAvb(data_dir_.Append("testkey_rsa4096.pem"));

    // Makes a vbmeta image includeing 'boot' and 'system' chained descriptors.
    auto vbmeta_path = GenerateVBMetaImage("vbmeta.img", "SHA256_RSA8192", 0,
                                           data_dir_.Append("testkey_rsa8192.pem"),
                                           {}, /* include_descriptor_image_paths */
                                           {{"boot", 1, rsa2048_public_key}, /* chain_partitions */
                                            {"system", 2, rsa4096_public_key}},
                                           "--internal_release_string \"unit test\"");

    // Calculates the digest of all chained partitions, to ensure the chained is formed properly.
    EXPECT_EQ("abbe11b316901f3336e26630f64c4732dadbe14532186ac8640e4141a403721f",
              CalcVBMetaDigest("vbmeta.img", "sha256"));

    // Invokes the public API from fs_avb.h.
    auto vbmeta_image_path = [this](const std::string& partition_name) {
        return test_dir_.Append(partition_name + ".img").value();
    };
    auto avb_handle = AvbHandle::LoadAndVerifyVbmeta(
            "vbmeta" /* partition_name */, "" /* ab_suffix */, "" /* other_suffix */,
            "" /* expected_public_key_blob*/, HashAlgorithm::kSHA256,
            false /* allow_verification_error */, true /* load_chained_vbmeta */,
            true /* rollback_protection */, vbmeta_image_path);
    EXPECT_NE(nullptr, avb_handle);
    EXPECT_EQ(AvbHandleStatus::kSuccess, avb_handle->status());

    // Checks the summary info for all vbmeta images.
    // Checks the digest matches the value calculated by CalcVBMetaDigest().
    EXPECT_EQ("abbe11b316901f3336e26630f64c4732dadbe14532186ac8640e4141a403721f",
              avb_handle->vbmeta_info().digest);
    EXPECT_EQ(8576UL, avb_handle->vbmeta_info().total_size);
    EXPECT_EQ(HashAlgorithm::kSHA256, avb_handle->vbmeta_info().hash_algorithm);

    // Skip loading chained vbmeta.
    avb_handle = AvbHandle::LoadAndVerifyVbmeta(
            "vbmeta" /* partition_name */, "" /* ab_suffix */, "" /* other_suffix */,
            "" /* expected_public_key_blob*/, HashAlgorithm::kSHA256,
            false /* allow_verification_error */, false /* load_chained_vbmeta */,
            true /* rollback_protection */, vbmeta_image_path);
    EXPECT_NE(nullptr, avb_handle);
    EXPECT_EQ(AvbHandleStatus::kSuccess, avb_handle->status());
    EXPECT_EQ("5c31197992b3c72a854ec7dc0eb9609ffebcffab7917ffd381a99ecee328f09c",
              avb_handle->vbmeta_info().digest);
    EXPECT_EQ(5184UL, avb_handle->vbmeta_info().total_size);
    EXPECT_EQ(HashAlgorithm::kSHA256, avb_handle->vbmeta_info().hash_algorithm);
}

TEST_F(PublicFsAvbTest, LoadAndVerifyVbmetaWithModifications) {
    // Generates a raw boot.img
    const size_t boot_image_size = 5 * 1024 * 1024;
    const size_t boot_partition_size = 10 * 1024 * 1024;
    base::FilePath boot_path = GenerateImage("boot.img", boot_image_size);

    // Adds AVB Hash Footer.
    AddAvbFooter(boot_path, "hash", "boot", boot_partition_size, "SHA256_RSA2048", 10,
                 data_dir_.Append("testkey_rsa2048.pem"), "d00df00d",
                 "--internal_release_string \"unit test\"");

    // Generates a raw system.img, use a smaller size to speed-up unit test.
    const size_t system_image_size = 10 * 1024 * 1024;
    const size_t system_partition_size = 15 * 1024 * 1024;
    base::FilePath system_path = GenerateImage("system.img", system_image_size);
    // Adds AVB Hashtree Footer.
    AddAvbFooter(system_path, "hashtree", "system", system_partition_size, "SHA512_RSA4096", 20,
                 data_dir_.Append("testkey_rsa4096.pem"), "d00df00d",
                 "--internal_release_string \"unit test\"");

    // Generates chain partition descriptors.
    base::FilePath rsa2048_public_key =
            ExtractPublicKeyAvb(data_dir_.Append("testkey_rsa2048.pem"));
    base::FilePath rsa4096_public_key =
            ExtractPublicKeyAvb(data_dir_.Append("testkey_rsa4096.pem"));

    // Makes a vbmeta image includeing 'boot' and 'system' chained descriptors.
    auto vbmeta_path = GenerateVBMetaImage("vbmeta.img", "SHA256_RSA8192", 0,
                                           data_dir_.Append("testkey_rsa8192.pem"),
                                           {}, /* include_descriptor_image_paths */
                                           {{"boot", 1, rsa2048_public_key}, /* chain_partitions */
                                            {"system", 2, rsa4096_public_key}},
                                           "--internal_release_string \"unit test\"");

    // Calculates the digest of all chained partitions, to ensure the chained is formed properly.
    EXPECT_EQ("abbe11b316901f3336e26630f64c4732dadbe14532186ac8640e4141a403721f",
              CalcVBMetaDigest("vbmeta.img", "sha256"));

    // Sets AVB_VBMETA_IMAGE_FLAGS_HASHTREE_DISABLED in the vbmeta.img.
    ModifyVBMetaHeaderFlags(vbmeta_path, AVB_VBMETA_IMAGE_FLAGS_HASHTREE_DISABLED);

    auto vbmeta_image_path = [this](const std::string& partition_name) {
        return test_dir_.Append(partition_name + ".img").value();
    };
    auto avb_handle = AvbHandle::LoadAndVerifyVbmeta(
            "vbmeta" /* partition_name */, "" /* ab_suffix */, "" /* other_suffix */,
            "" /* expected_public_key_blob*/, HashAlgorithm::kSHA256,
            false /* allow_verification_error */, true /* load_chained_vbmeta */,
            true /* rollback_protection */, vbmeta_image_path);
    // Returns a null handler because allow_verification is not True.
    EXPECT_EQ(nullptr, avb_handle);

    // Try again with allow_verification_error set to true.
    avb_handle = AvbHandle::LoadAndVerifyVbmeta(
            "vbmeta" /* partition_name */, "" /* ab_suffix */, "" /* other_suffix */,
            "" /* expected_public_key_blob*/, HashAlgorithm::kSHA256,
            true /* allow_verification_error */, true /* load_chained_vbmeta */,
            true /* rollback_protection */, vbmeta_image_path);
    EXPECT_NE(nullptr, avb_handle);
    EXPECT_EQ(AvbHandleStatus::kHashtreeDisabled, avb_handle->status());

    // Checks the summary info for all vbmeta images.
    // Checks the digest matches the value calculated by CalcVBMetaDigest().
    EXPECT_EQ("ae8f7ad95cbb7ce4f0feeeedc2a0a39824af5cd29dad4d028597cab4b8c2e83c",
              CalcVBMetaDigest("vbmeta.img", "sha256"));
    EXPECT_EQ("ae8f7ad95cbb7ce4f0feeeedc2a0a39824af5cd29dad4d028597cab4b8c2e83c",
              avb_handle->vbmeta_info().digest);
    EXPECT_EQ(8576UL, avb_handle->vbmeta_info().total_size);
    EXPECT_EQ(HashAlgorithm::kSHA256, avb_handle->vbmeta_info().hash_algorithm);

    // Sets AVB_VBMETA_IMAGE_FLAGS_VERIFICATION_DISABLED in the vbmeta.img.
    ModifyVBMetaHeaderFlags(vbmeta_path, AVB_VBMETA_IMAGE_FLAGS_VERIFICATION_DISABLED);
    // Loads the vbmeta with allow_verification_error set to true.
    avb_handle = AvbHandle::LoadAndVerifyVbmeta(
            "vbmeta" /* partition_name */, "" /* ab_suffix */, "" /* other_suffix */,
            "" /* expected_public_key_blob*/, HashAlgorithm::kSHA256,
            true /* allow_verification_error */, true /* load_chained_vbmeta */,
            true /* rollback_protection */, vbmeta_image_path);
    EXPECT_NE(nullptr, avb_handle);
    EXPECT_EQ(AvbHandleStatus::kVerificationDisabled, avb_handle->status());
    // Only the top-level vbmeta.img is loaded, when VERIFICATION_DISABLED is set.
    // However, CalcVBMetaDigest() reads all vbmeta structs to calculate the digest,
    // including vbmeta.img, boot.img and syste.img. So we don't compare the digest here.
    EXPECT_EQ(5184UL, avb_handle->vbmeta_info().total_size);

    // Sets a unknown flag in the vbmeta.imgm and expects to get
    // AvbHandleStatus::kVerificationError.
    ModifyVBMetaHeaderFlags(vbmeta_path, 0x10000000);
    // Loads the vbmeta with allow_verification_error set to true.
    avb_handle = AvbHandle::LoadAndVerifyVbmeta(
            "vbmeta" /* partition_name */, "" /* ab_suffix */, "" /* other_suffix */,
            "" /* expected_public_key_blob*/, HashAlgorithm::kSHA256,
            true /* allow_verification_error */, true /* load_chained_vbmeta */,
            true /* rollback_protection */, vbmeta_image_path);
    EXPECT_NE(nullptr, avb_handle);
    EXPECT_EQ(AvbHandleStatus::kVerificationError, avb_handle->status());
    // Checks the digest matches the value calculated by CalcVBMetaDigest().
    EXPECT_EQ("8fb99c4f54500053c3582df5eaf04e9a533137398879188aad9968ec19a664f1",
              CalcVBMetaDigest("vbmeta.img", "sha256"));
    EXPECT_EQ("8fb99c4f54500053c3582df5eaf04e9a533137398879188aad9968ec19a664f1",
              avb_handle->vbmeta_info().digest);
    EXPECT_EQ(8576UL, avb_handle->vbmeta_info().total_size);
    EXPECT_EQ(HashAlgorithm::kSHA256, avb_handle->vbmeta_info().hash_algorithm);
}

TEST_F(PublicFsAvbTest, LoadAndVerifyVbmetaWithPublicKeys) {
    // Generates a raw boot.img
    const size_t boot_image_size = 5 * 1024 * 1024;
    const size_t boot_partition_size = 10 * 1024 * 1024;
    base::FilePath boot_path = GenerateImage("boot.img", boot_image_size);

    // Adds AVB Hash Footer.
    AddAvbFooter(boot_path, "hash", "boot", boot_partition_size, "SHA256_RSA2048", 10,
                 data_dir_.Append("testkey_rsa2048.pem"), "d00df00d",
                 "--internal_release_string \"unit test\"");

    // Generates a raw system.img, use a smaller size to speed-up unit test.
    const size_t system_image_size = 10 * 1024 * 1024;
    const size_t system_partition_size = 15 * 1024 * 1024;
    base::FilePath system_path = GenerateImage("system.img", system_image_size);
    // Adds AVB Hashtree Footer.
    AddAvbFooter(system_path, "hashtree", "system", system_partition_size, "SHA512_RSA4096", 20,
                 data_dir_.Append("testkey_rsa4096.pem"), "d00df00d",
                 "--internal_release_string \"unit test\"");

    // Generates chain partition descriptors.
    base::FilePath rsa2048_public_key =
            ExtractPublicKeyAvb(data_dir_.Append("testkey_rsa2048.pem"));
    base::FilePath rsa4096_public_key =
            ExtractPublicKeyAvb(data_dir_.Append("testkey_rsa4096.pem"));
    base::FilePath rsa8192_public_key =
            ExtractPublicKeyAvb(data_dir_.Append("testkey_rsa8192.pem"));

    // Makes a vbmeta image includeing 'boot' and 'vbmeta_system' chained descriptors.
    auto vbmeta_path = GenerateVBMetaImage("vbmeta.img", "SHA256_RSA8192", 0,
                                           data_dir_.Append("testkey_rsa8192.pem"),
                                           {}, /* include_descriptor_image_paths */
                                           {{"boot", 1, rsa2048_public_key}, /* chain_partitions */
                                            {"system", 2, rsa4096_public_key}},
                                           "--internal_release_string \"unit test\"");

    auto vbmeta_image_path = [this](const std::string& partition_name) {
        return test_dir_.Append(partition_name + ".img").value();
    };
    std::vector<VBMetaData> vbmeta_images;
    // Uses the correct expected public key.
    auto avb_handle = AvbHandle::LoadAndVerifyVbmeta(
            "vbmeta" /* partition_name */, "" /* ab_suffix */, "" /* other_suffix */,
            rsa8192_public_key.value(), HashAlgorithm::kSHA256, true /* allow_verification_error */,
            true /* load_chained_vbmeta */, true /* rollback_protection */, vbmeta_image_path);
    EXPECT_NE(nullptr, avb_handle);
    EXPECT_EQ(AvbHandleStatus::kSuccess, avb_handle->status());

    // Uses a non-existed public key.
    avb_handle = AvbHandle::LoadAndVerifyVbmeta(
            "vbmeta" /* partition_name */, "" /* ab_suffix */, "" /* other_suffix */,
            "/path/to/non-existed/key", HashAlgorithm::kSHA256, true /* allow_verification_error */,
            true /* load_chained_vbmeta */, true /* rollback_protection */, vbmeta_image_path);
    EXPECT_EQ(nullptr, avb_handle);

    // Uses an incorrect public key, with allow_verification_error false.
    avb_handle = AvbHandle::LoadAndVerifyVbmeta(
            "vbmeta" /* partition_name */, "" /* ab_suffix */, "" /* other_suffix */,
            rsa4096_public_key.value(), HashAlgorithm::kSHA256,
            false /* allow_verification_error */, true /* load_chained_vbmeta */,
            true /* rollback_protection */, vbmeta_image_path);
    EXPECT_EQ(nullptr, avb_handle);

    // Uses an incorrect public key, with allow_verification_error true.
    avb_handle = AvbHandle::LoadAndVerifyVbmeta(
            "vbmeta" /* partition_name */, "" /* ab_suffix */, "" /* other_suffix */,
            rsa4096_public_key.value(), HashAlgorithm::kSHA256, true /* allow_verification_error */,
            true /* load_chained_vbmeta */, true /* rollback_protection */, vbmeta_image_path);
    EXPECT_NE(nullptr, avb_handle);
    EXPECT_EQ(AvbHandleStatus::kVerificationError, avb_handle->status());
}

}  // namespace fs_avb_host_test

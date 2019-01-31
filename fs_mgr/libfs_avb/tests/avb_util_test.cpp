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

#include <android-base/unique_fd.h>
#include <base/files/file_util.h>
#include <base/rand_util.h>
#include <base/strings/string_util.h>
#include <libavb/libavb.h>

#include "avb_util.h"
#include "fs_avb_test_util.h"

// Target classes or functions to test:
using android::fs_mgr::AvbPartitionToDevicePatition;
using android::fs_mgr::DeriveAvbPartitionName;
using android::fs_mgr::FstabEntry;
using android::fs_mgr::GetAvbFooter;
using android::fs_mgr::GetChainPartitionInfo;
using android::fs_mgr::GetTotalSize;
using android::fs_mgr::LoadAndVerifyVbmetaByPartition;
using android::fs_mgr::LoadAndVerifyVbmetaByPath;
using android::fs_mgr::VBMetaData;
using android::fs_mgr::VBMetaVerifyResult;
using android::fs_mgr::VerifyPublicKeyBlob;
using android::fs_mgr::VerifyVBMetaData;
using android::fs_mgr::VerifyVBMetaSignature;

namespace fs_avb_host_test {

class AvbUtilTest : public BaseFsAvbTest {
  public:
    AvbUtilTest(){};

  protected:
    ~AvbUtilTest(){};
    // Helper function for VerifyVBMetaSignature test. Modifies vbmeta.data()
    // in a number of places at |offset| of size |length| and checks that
    // VerifyVBMetaSignature() returns |expected_result|.
    bool TestVBMetaModification(VBMetaVerifyResult expected_result, const VBMetaData& vbmeta,
                                size_t offset, size_t length);
    // Modifies a random bit for a file, in the range of [offset, offset + length - 1].
    void ModifyFile(const base::FilePath& file_path, size_t offset, ssize_t length);

    // Loads the content of avb_image_path and comparies it with the content of vbmeta.
    bool CompareVBMeta(const base::FilePath& avb_image_path, const VBMetaData& expected_vbmeta);

    // Sets the flas in vbmeta header, the image_path could be a vbmeta.img or a system.img.
    void SetVBMetaFlags(const base::FilePath& image_path, uint32_t flags);
};

void AvbUtilTest::SetVBMetaFlags(const base::FilePath& image_path, uint32_t flags) {
    if (!base::PathExists(image_path)) return;

    std::string image_file_name = image_path.RemoveExtension().BaseName().value();
    bool is_vbmeta_partition =
        base::StartsWith(image_file_name, "vbmeta", base::CompareCase::INSENSITIVE_ASCII);

    android::base::unique_fd fd(open(image_path.value().c_str(), O_RDWR | O_CLOEXEC));
    EXPECT_TRUE(fd > 0);

    uint64_t vbmeta_offset = 0;  // for vbmeta.img
    if (!is_vbmeta_partition) {
        std::unique_ptr<AvbFooter> footer = GetAvbFooter(fd);
        EXPECT_NE(nullptr, footer);
        vbmeta_offset = footer->vbmeta_offset;
    }

    auto flags_offset = vbmeta_offset + offsetof(AvbVBMetaImageHeader, flags);
    uint32_t flags_data = htobe32(flags);
    EXPECT_EQ(flags_offset, lseek64(fd, flags_offset, SEEK_SET));
    EXPECT_EQ(sizeof flags_data, write(fd, &flags_data, sizeof flags_data));
}

TEST_F(AvbUtilTest, AvbPartitionToDevicePatition) {
    EXPECT_EQ("system", AvbPartitionToDevicePatition("system", "", ""));
    EXPECT_EQ("system", AvbPartitionToDevicePatition("system", "", "_b"));

    EXPECT_EQ("system_a", AvbPartitionToDevicePatition("system", "_a", ""));
    EXPECT_EQ("system_a", AvbPartitionToDevicePatition("system", "_a", "_b"));

    EXPECT_EQ("system_b", AvbPartitionToDevicePatition("system_other", "", "_b"));
    EXPECT_EQ("system_b", AvbPartitionToDevicePatition("system_other", "_a", "_b"));
}

TEST_F(AvbUtilTest, DeriveAvbPartitionName) {
    // The fstab_entry to test.
    FstabEntry fstab_entry = {
        .blk_device = "/dev/block/dm-1",  // a dm-linear device (logical)
        .mount_point = "/system",
        .fs_type = "ext4",
        .logical_partition_name = "system",
    };

    // Logical partitions.
    // non-A/B
    fstab_entry.fs_mgr_flags.logical = true;
    EXPECT_EQ("system", DeriveAvbPartitionName(fstab_entry, "_dont_care", "_dont_care"));
    EXPECT_EQ("system", DeriveAvbPartitionName(fstab_entry, "_a", "_b"));
    EXPECT_EQ("system", DeriveAvbPartitionName(fstab_entry, "", ""));
    // Active slot.
    fstab_entry.fs_mgr_flags.slot_select = true;
    fstab_entry.logical_partition_name = "system_a";
    EXPECT_EQ("system", DeriveAvbPartitionName(fstab_entry, "_a", "_dont_care"));
    EXPECT_EQ("system", DeriveAvbPartitionName(fstab_entry, "_a", "_b"));
    EXPECT_EQ("system", DeriveAvbPartitionName(fstab_entry, "_a", ""));
    EXPECT_EQ("system_a", DeriveAvbPartitionName(fstab_entry, "_wont_erase_a", "_dont_care"));
    // The other slot.
    fstab_entry.fs_mgr_flags.slot_select = false;
    fstab_entry.fs_mgr_flags.slot_select_other = true;
    fstab_entry.logical_partition_name = "system_b";
    EXPECT_EQ("system_other", DeriveAvbPartitionName(fstab_entry, "_dont_care", "_b"));
    EXPECT_EQ("system_other", DeriveAvbPartitionName(fstab_entry, "_a", "_b"));
    EXPECT_EQ("system_other", DeriveAvbPartitionName(fstab_entry, "", "_b"));
    EXPECT_EQ("system_b_other", DeriveAvbPartitionName(fstab_entry, "_dont_care", "_wont_erase_b"));

    // Non-logical partitions.
    // non-A/B.
    fstab_entry.fs_mgr_flags.logical = false;
    fstab_entry.fs_mgr_flags.slot_select = false;
    fstab_entry.fs_mgr_flags.slot_select_other = false;
    fstab_entry.blk_device = "/dev/block/by-name/system";
    EXPECT_EQ("system", DeriveAvbPartitionName(fstab_entry, "_dont_care", "_dont_care"));
    EXPECT_EQ("system", DeriveAvbPartitionName(fstab_entry, "_a", "_b"));
    EXPECT_EQ("system", DeriveAvbPartitionName(fstab_entry, "", ""));
    // Active slot _a.
    fstab_entry.fs_mgr_flags.slot_select = true;
    fstab_entry.blk_device = "/dev/block/by-name/system_a";
    EXPECT_EQ("system", DeriveAvbPartitionName(fstab_entry, "_a", "_dont_care"));
    EXPECT_EQ("system", DeriveAvbPartitionName(fstab_entry, "_a", "_b"));
    EXPECT_EQ("system", DeriveAvbPartitionName(fstab_entry, "_a", ""));
    EXPECT_EQ("system_a", DeriveAvbPartitionName(fstab_entry, "_wont_erase_a", "_dont_care"));
    // Inactive slot _b.
    fstab_entry.fs_mgr_flags.slot_select = false;
    fstab_entry.fs_mgr_flags.slot_select_other = true;
    fstab_entry.blk_device = "/dev/block/by-name/system_b";
    EXPECT_EQ("system_other", DeriveAvbPartitionName(fstab_entry, "dont_care", "_b"));
    EXPECT_EQ("system_other", DeriveAvbPartitionName(fstab_entry, "_a", "_b"));
    EXPECT_EQ("system_other", DeriveAvbPartitionName(fstab_entry, "", "_b"));
    EXPECT_EQ("system_b_other", DeriveAvbPartitionName(fstab_entry, "dont_care", "_wont_erase_b"));
}

TEST_F(AvbUtilTest, GetFdTotalSize) {
    // Generates a raw test.img via BaseFsAvbTest.
    const size_t image_size = 5 * 1024 * 1024;
    base::FilePath image_path = GenerateImage("test.img", image_size);

    // Checks file size is as expected via base::GetFileSize().
    int64_t file_size;
    ASSERT_TRUE(base::GetFileSize(image_path, &file_size));
    EXPECT_EQ(image_size, file_size);

    // Checks file size is expected via libfs_avb internal utils.
    auto fd = OpenUniqueReadFd(image_path);
    EXPECT_EQ(image_size, GetTotalSize(fd));
}

TEST_F(AvbUtilTest, GetFdTotalSizeWithOffset) {
    // Generates a raw test.img via BaseFsAvbTest.
    const size_t image_size = 10 * 1024 * 1024;
    base::FilePath image_path = GenerateImage("test.img", image_size);

    // Checks file size is expected even with a non-zero offset at the beginning.
    auto fd = OpenUniqueReadFd(image_path);
    off_t initial_offset = 2019;
    EXPECT_EQ(initial_offset, lseek(fd, initial_offset, SEEK_SET));
    EXPECT_EQ(image_size, GetTotalSize(fd));            // checks that total size is still returned.
    EXPECT_EQ(initial_offset, lseek(fd, 0, SEEK_CUR));  // checks original offset is restored.
}

TEST_F(AvbUtilTest, GetAvbFooter) {
    // Generates a raw system.img
    const size_t image_size = 10 * 1024 * 1024;
    const size_t partition_size = 15 * 1024 * 1024;
    base::FilePath system_path = GenerateImage("system.img", image_size);
    EXPECT_NE(0U, system_path.value().size());

    // Checks image size is as expected.
    int64_t file_size;
    ASSERT_TRUE(base::GetFileSize(system_path, &file_size));
    EXPECT_EQ(image_size, file_size);

    // Appends AVB Hashtree Footer.
    AddAvbFooter(system_path, "hashtree", "system", partition_size, "SHA512_RSA8192", 20,
                 data_dir_.Append("testkey_rsa8192.pem"), "d00df00d",
                 "--internal_release_string \"unit test\"");

    // Checks partition size is as expected, after adding footer.
    ASSERT_TRUE(base::GetFileSize(system_path, &file_size));
    EXPECT_EQ(partition_size, file_size);

    // Checks avb footer and avb vbmeta.
    EXPECT_EQ(
            "Footer version:           1.0\n"
            "Image size:               15728640 bytes\n"
            "Original image size:      10485760 bytes\n"
            "VBMeta offset:            10661888\n"
            "VBMeta size:              3648 bytes\n"
            "--\n"
            "Minimum libavb version:   1.0\n"
            "Header Block:             256 bytes\n"
            "Authentication Block:     1088 bytes\n"
            "Auxiliary Block:          2304 bytes\n"
            "Algorithm:                SHA512_RSA8192\n"
            "Rollback Index:           20\n"
            "Flags:                    0\n"
            "Release String:           'unit test'\n"
            "Descriptors:\n"
            "    Hashtree descriptor:\n"
            "      Version of dm-verity:  1\n"
            "      Image Size:            10485760 bytes\n"
            "      Tree Offset:           10485760\n"
            "      Tree Size:             86016 bytes\n"
            "      Data Block Size:       4096 bytes\n"
            "      Hash Block Size:       4096 bytes\n"
            "      FEC num roots:         2\n"
            "      FEC offset:            10571776\n"
            "      FEC size:              90112 bytes\n"
            "      Hash Algorithm:        sha1\n"
            "      Partition Name:        system\n"
            "      Salt:                  d00df00d\n"
            "      Root Digest:           a3d5dd307341393d85de356c384ff543ec1ed81b\n"
            "      Flags:                 0\n",
            InfoImage(system_path));

    // Checks each field from GetAvbFooter(fd).
    auto fd = OpenUniqueReadFd(system_path);
    auto footer = GetAvbFooter(fd);
    EXPECT_NE(nullptr, footer);
    EXPECT_EQ(10485760, footer->original_image_size);
    EXPECT_EQ(10661888, footer->vbmeta_offset);
    EXPECT_EQ(3648, footer->vbmeta_size);
}

TEST_F(AvbUtilTest, GetAvbFooterErrorVerification) {
    // Generates a raw system.img
    const size_t image_size = 5 * 1024 * 1024;
    base::FilePath system_path = GenerateImage("system.img", image_size);

    // Checks each field from GetAvbFooter(fd).
    auto fd = OpenUniqueReadFd(system_path);
    auto footer = GetAvbFooter(fd);
    EXPECT_EQ(nullptr, footer);
}

TEST_F(AvbUtilTest, GetAvbFooterInsufficientSize) {
    // Generates a raw system.img
    const size_t image_size = AVB_FOOTER_SIZE - 10;
    base::FilePath system_path = GenerateImage("system.img", image_size);

    // Checks each field from GetAvbFooter(fd).
    auto fd = OpenUniqueReadFd(system_path);
    auto footer = GetAvbFooter(fd);
    EXPECT_EQ(nullptr, footer);
}

TEST_F(AvbUtilTest, GetVBMetaHeader) {
    // Generates a raw boot.img
    const size_t image_size = 5 * 1024 * 1024;
    const size_t partition_size = 10 * 1024 * 1024;
    base::FilePath boot_path = GenerateImage("boot.img", image_size);
    // Appends AVB Hash Footer.
    AddAvbFooter(boot_path, "hash", "boot", partition_size, "SHA256_RSA4096", 10,
                 data_dir_.Append("testkey_rsa4096.pem"), "d00df00d",
                 "--internal_release_string \"unit test\"");
    // Extracts boot vbmeta from boot.img into boot-vbmeta.img.
    base::FilePath boot_vbmeta = ExtractVBMetaImage(boot_path, "boot-vbmeta.img");
    EXPECT_EQ(
            "Minimum libavb version:   1.0\n"
            "Header Block:             256 bytes\n"
            "Authentication Block:     576 bytes\n"
            "Auxiliary Block:          1216 bytes\n"
            "Algorithm:                SHA256_RSA4096\n"
            "Rollback Index:           10\n"
            "Flags:                    0\n"
            "Release String:           'unit test'\n"
            "Descriptors:\n"
            "    Hash descriptor:\n"
            "      Image Size:            5242880 bytes\n"
            "      Hash Algorithm:        sha256\n"
            "      Partition Name:        boot\n"
            "      Salt:                  d00df00d\n"
            "      Digest:                "
            "222dd01e98284a1fcd7781f85d1392e43a530511a64eff96db197db90ebc4df1\n"
            "      Flags:                 0\n",
            InfoImage("boot-vbmeta.img"));

    // Creates a VBMetaData with the content from boot-vbmeta.img.
    std::string content;
    EXPECT_TRUE(base::ReadFileToString(boot_vbmeta, &content));
    VBMetaData vbmeta((uint8_t*)content.data(), content.size(), "boot-vbmeta");
    EXPECT_EQ(content.size(), vbmeta.size());

    // Checks each field returned from GetVBMetaHeader().
    auto vbmeta_header = vbmeta.GetVBMetaHeader(false /* update_vbmeta_size */);
    EXPECT_NE(nullptr, vbmeta_header);
    EXPECT_EQ(576, vbmeta_header->authentication_data_block_size);
    EXPECT_EQ(1216, vbmeta_header->auxiliary_data_block_size);
    EXPECT_EQ(AVB_ALGORITHM_TYPE_SHA256_RSA4096, vbmeta_header->algorithm_type);
    EXPECT_EQ(0, vbmeta_header->hash_offset);
    EXPECT_EQ(32, vbmeta_header->hash_size);
    EXPECT_EQ(32, vbmeta_header->signature_offset);
    EXPECT_EQ(512, vbmeta_header->signature_size);
    EXPECT_EQ(176, vbmeta_header->public_key_offset);
    EXPECT_EQ(1032, vbmeta_header->public_key_size);
    EXPECT_EQ(0, vbmeta_header->descriptors_offset);
    EXPECT_EQ(176, vbmeta_header->descriptors_size);
    EXPECT_EQ(10, vbmeta_header->rollback_index);
    EXPECT_EQ(0, vbmeta_header->flags);
    EXPECT_EQ("unit test", std::string((const char*)vbmeta_header->release_string));

    // Appends some garbage to the end of the vbmeta buffer, checks it still can work.
    std::string padding(2020, 'A');  // Generate a padding with length 2020.
    std::string content_padding = content + padding;
    VBMetaData vbmeta_padding((const uint8_t*)content_padding.data(), content_padding.size(),
                              "boot");
    EXPECT_EQ(content_padding.size(), vbmeta_padding.size());

    // Checks each field still can be parsed properly, even with garbage padding.
    vbmeta_header = vbmeta_padding.GetVBMetaHeader(false /* update_vbmeta_size */);
    EXPECT_NE(nullptr, vbmeta_header);
    EXPECT_EQ(576, vbmeta_header->authentication_data_block_size);
    EXPECT_EQ(1216, vbmeta_header->auxiliary_data_block_size);
    EXPECT_EQ(AVB_ALGORITHM_TYPE_SHA256_RSA4096, vbmeta_header->algorithm_type);
    EXPECT_EQ(0, vbmeta_header->hash_offset);
    EXPECT_EQ(32, vbmeta_header->hash_size);
    EXPECT_EQ(32, vbmeta_header->signature_offset);
    EXPECT_EQ(512, vbmeta_header->signature_size);
    EXPECT_EQ(176, vbmeta_header->public_key_offset);
    EXPECT_EQ(1032, vbmeta_header->public_key_size);
    EXPECT_EQ(0, vbmeta_header->descriptors_offset);
    EXPECT_EQ(176, vbmeta_header->descriptors_size);
    EXPECT_EQ(10, vbmeta_header->rollback_index);
    EXPECT_EQ(0, vbmeta_header->flags);
    EXPECT_EQ("unit test", std::string((const char*)vbmeta_header->release_string));

    // Checks vbmeta size is updated to the actual size without padding.
    vbmeta_header = vbmeta_padding.GetVBMetaHeader(true /* update_vbmeta_size */);
    EXPECT_EQ(content_padding.size() - padding.size(), vbmeta_padding.size());
}

TEST_F(AvbUtilTest, VerifyPublicKeyBlob) {
    // Generates a raw key.bin
    const size_t key_size = 2048;
    base::FilePath key_path = GenerateImage("key.bin", key_size);

    uint8_t key_data[key_size];
    EXPECT_EQ(key_size, base::ReadFile(key_path, (char*)key_data, key_size));

    std::string expected_key_blob;
    EXPECT_TRUE(base::ReadFileToString(key_path, &expected_key_blob));
    EXPECT_TRUE(VerifyPublicKeyBlob(key_data, key_size, expected_key_blob));

    key_data[10] ^= 0x80;  // toggles a bit and expects a failure
    EXPECT_FALSE(VerifyPublicKeyBlob(key_data, key_size, expected_key_blob));
    key_data[10] ^= 0x80;  // toggles the bit again, should pass
    EXPECT_TRUE(VerifyPublicKeyBlob(key_data, key_size, expected_key_blob));
}

TEST_F(AvbUtilTest, VerifyEmptyPublicKeyBlob) {
    // Generates a raw key.bin
    const size_t key_size = 2048;
    base::FilePath key_path = GenerateImage("key.bin", key_size);

    uint8_t key_data[key_size];
    EXPECT_EQ(key_size, base::ReadFile(key_path, (char*)key_data, key_size));

    std::string expected_key_blob = "";  // empty means no expectation, thus return true.
    EXPECT_TRUE(VerifyPublicKeyBlob(key_data, key_size, expected_key_blob));
}

TEST_F(AvbUtilTest, VerifyVBMetaSignature) {
    const size_t image_size = 10 * 1024 * 1024;
    const size_t partition_size = 15 * 1024 * 1024;
    auto signing_key = data_dir_.Append("testkey_rsa4096.pem");
    auto vbmeta = GenerateImageAndExtractVBMetaData("system", image_size, partition_size,
                                                    "hashtree", signing_key, "SHA256_RSA4096",
                                                    10 /* rollback_index */);

    auto expected_public_key = ExtractPublicKeyAvbBlob(signing_key);
    EXPECT_EQ(VBMetaVerifyResult::kSuccess, VerifyVBMetaSignature(vbmeta, expected_public_key));

    // Converts the expected key into an 'unexpected' key.
    expected_public_key[10] ^= 0x80;
    EXPECT_EQ(VBMetaVerifyResult::kErrorVerification,
              VerifyVBMetaSignature(vbmeta, expected_public_key));
}

bool AvbUtilTest::TestVBMetaModification(VBMetaVerifyResult expected_result,
                                         const VBMetaData& vbmeta, size_t offset, size_t length) {
    uint8_t* d = reinterpret_cast<uint8_t*>(vbmeta.data());
    const int kNumCheckIntervals = 8;

    // Tests |kNumCheckIntervals| modifications in the start, middle, and
    // end of the given sub-array at offset with size.
    for (int n = 0; n <= kNumCheckIntervals; n++) {
        size_t o = std::min(length * n / kNumCheckIntervals, length - 1) + offset;
        d[o] ^= 0x80;
        VBMetaVerifyResult result = VerifyVBMetaSignature(vbmeta, "" /* expected_public_key */);
        d[o] ^= 0x80;
        if (result != expected_result) {
            return false;
        }
    }

    return true;
}

TEST_F(AvbUtilTest, VerifyVBMetaSignatureWithModification) {
    const size_t image_size = 10 * 1024 * 1024;
    const size_t partition_size = 15 * 1024 * 1024;
    auto signing_key = data_dir_.Append("testkey_rsa4096.pem");
    auto vbmeta = GenerateImageAndExtractVBMetaData("system", image_size, partition_size,
                                                    "hashtree", signing_key, "SHA256_RSA4096",
                                                    10 /* rollback_index */);

    auto header = vbmeta.GetVBMetaHeader(true /* update_vbmeta_size */);
    size_t header_block_offset = 0;
    size_t authentication_block_offset = header_block_offset + sizeof(AvbVBMetaImageHeader);
    size_t auxiliary_block_offset =
            authentication_block_offset + header->authentication_data_block_size;

    // Should detect modifications in the auxiliary data block.
    EXPECT_TRUE(TestVBMetaModification(VBMetaVerifyResult::kErrorVerification, vbmeta,
                                       auxiliary_block_offset, header->auxiliary_data_block_size));

    // Sholud detect modifications in the hash part of authentication data block.
    EXPECT_TRUE(TestVBMetaModification(VBMetaVerifyResult::kErrorVerification, vbmeta,
                                       authentication_block_offset + header->hash_offset,
                                       header->hash_size));

    // Sholud detect modifications in the signature part of authentication data block.
    EXPECT_TRUE(TestVBMetaModification(VBMetaVerifyResult::kErrorVerification, vbmeta,
                                       authentication_block_offset + header->signature_offset,
                                       header->signature_size));
}

TEST_F(AvbUtilTest, VerifyVBMetaSignatureNotSigned) {
    const size_t image_size = 10 * 1024 * 1024;
    const size_t partition_size = 15 * 1024 * 1024;
    auto vbmeta = GenerateImageAndExtractVBMetaData(
            "system", image_size, partition_size, "hashtree", {} /* avb_signing_key */,
            "" /* avb_algorithm */, 10 /* rollback_index */);

    EXPECT_EQ(VBMetaVerifyResult::kErrorVerification, VerifyVBMetaSignature(vbmeta, ""));
}

TEST_F(AvbUtilTest, VerifyVBMetaSignatureInvalidVBMeta) {
    const size_t buffer_size = 5 * 1024 * 1024;
    std::vector<uint8_t> vbmeta_buffer(buffer_size);
    for (size_t n = 0; n < buffer_size; n++) {
        vbmeta_buffer[n] = uint8_t(n);
    }

    VBMetaData invalid_vbmeta((const uint8_t*)vbmeta_buffer.data(), vbmeta_buffer.size(),
                              "invalid_vbmeta");
    EXPECT_EQ(VBMetaVerifyResult::kError, VerifyVBMetaSignature(invalid_vbmeta, ""));
}

bool AvbUtilTest::CompareVBMeta(const base::FilePath& avb_image_path,
                                const VBMetaData& expected_vbmeta) {
    if (!base::PathExists(avb_image_path)) return false;

    std::string image_file_name = avb_image_path.RemoveExtension().BaseName().value();

    base::FilePath extracted_vbmeta_path;
    if (base::StartsWith(image_file_name, "vbmeta", base::CompareCase::INSENSITIVE_ASCII)) {
        extracted_vbmeta_path = avb_image_path;  // no need to extract if it's a vbmeta image.
    } else {
        extracted_vbmeta_path = ExtractVBMetaImage(avb_image_path, image_file_name + "-vbmeta.img");
    }

    // Gets file size of the vbmeta image.
    int64_t extracted_vbmeta_size;
    EXPECT_TRUE(base::GetFileSize(extracted_vbmeta_path, &extracted_vbmeta_size));

    // Reads the vbmeta into a vector.
    std::vector<uint8_t> extracted_vbmeta_content(extracted_vbmeta_size);
    EXPECT_TRUE(base::ReadFile(extracted_vbmeta_path,
                               reinterpret_cast<char*>(extracted_vbmeta_content.data()),
                               extracted_vbmeta_size));

    // Compares extracted_vbmeta_content with the expected_vbmeta.
    EXPECT_EQ(expected_vbmeta.size(), extracted_vbmeta_size);
    return memcmp(reinterpret_cast<void*>(extracted_vbmeta_content.data()),
                  reinterpret_cast<void*>(expected_vbmeta.data()), extracted_vbmeta_size) == 0;
}

TEST_F(AvbUtilTest, VerifyVBMetaDataWithoutFooter) {
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
    EXPECT_EQ(
            "Minimum libavb version:   1.0\n"
            "Header Block:             256 bytes\n"
            "Authentication Block:     1088 bytes\n"
            "Auxiliary Block:          3840 bytes\n"
            "Algorithm:                SHA256_RSA8192\n"
            "Rollback Index:           0\n"
            "Flags:                    0\n"
            "Release String:           'unit test'\n"
            "Descriptors:\n"
            "    Chain Partition descriptor:\n"
            "      Partition Name:          boot\n"
            "      Rollback Index Location: 1\n"
            "      Public key (sha1):       cdbb77177f731920bbe0a0f94f84d9038ae0617d\n"
            "    Chain Partition descriptor:\n"
            "      Partition Name:          system\n"
            "      Rollback Index Location: 2\n"
            "      Public key (sha1):       2597c218aae470a130f61162feaae70afd97f011\n",
            InfoImage("vbmeta.img"));

    android::base::unique_fd fd(open(vbmeta_path.value().c_str(), O_RDONLY | O_CLOEXEC));
    ASSERT_TRUE(fd > 0);

    VBMetaVerifyResult verify_result;
    std::unique_ptr<VBMetaData> vbmeta =
            VerifyVBMetaData(fd, "vbmeta", "" /*expected_public_key_blob */, &verify_result);
    EXPECT_TRUE(vbmeta != nullptr);
    EXPECT_EQ(VBMetaVerifyResult::kSuccess, verify_result);

    // Checkes the returned vbmeta content is the same as that extracted via avbtool.
    vbmeta->GetVBMetaHeader(true /* update_vbmeta_size */);
    EXPECT_TRUE(CompareVBMeta(vbmeta_path, *vbmeta));
}

TEST_F(AvbUtilTest, VerifyVBMetaDataWithFooter) {
    const size_t image_size = 10 * 1024 * 1024;
    const size_t partition_size = 15 * 1024 * 1024;
    base::FilePath system_path = GenerateImage("system.img", image_size);

    // Appends AVB Hashtree Footer.
    AddAvbFooter(system_path, "hashtree", "system", partition_size, "SHA512_RSA8192", 20,
                 data_dir_.Append("testkey_rsa8192.pem"), "d00df00d",
                 "--internal_release_string \"unit test\"");

    android::base::unique_fd fd(open(system_path.value().c_str(), O_RDONLY | O_CLOEXEC));
    ASSERT_TRUE(fd > 0);

    VBMetaVerifyResult verify_result;
    std::unique_ptr<VBMetaData> vbmeta =
            VerifyVBMetaData(fd, "system", "" /*expected_public_key_blob */, &verify_result);
    EXPECT_TRUE(vbmeta != nullptr);
    EXPECT_EQ(VBMetaVerifyResult::kSuccess, verify_result);

    // Checkes the returned vbmeta content is the same as that extracted via avbtool.
    EXPECT_TRUE(CompareVBMeta(system_path, *vbmeta));
}

// Modifies a random bit for a file, in the range of [offset, offset + length - 1].
// Length < 0 means only resets previous modification without introducing new modification.
void AvbUtilTest::ModifyFile(const base::FilePath& file_path, size_t offset, ssize_t length) {
    static int last_modified_location = -1;
    static std::string last_file_path;

    int64_t file_size;
    ASSERT_TRUE(base::GetFileSize(file_path, &file_size));

    std::vector<uint8_t> file_content(file_size);
    ASSERT_TRUE(base::ReadFile(file_path, reinterpret_cast<char*>(file_content.data()), file_size));

    // Resets previous modification for consecutive calls on the same file.
    if (last_file_path == file_path.value()) {
        file_content[last_modified_location] ^= 0x80;
    }

    // Introduces a new modification.
    if (length > 0) {
        int modify_location = base::RandInt(offset, offset + length - 1);
        file_content[modify_location] ^= 0x80;
        last_file_path = file_path.value();
        last_modified_location = modify_location;
    }

    ASSERT_EQ(file_size, static_cast<const size_t>(base::WriteFile(
                                 file_path, reinterpret_cast<const char*>(file_content.data()),
                                 file_content.size())));
}

TEST_F(AvbUtilTest, VerifyVBMetaDataError) {
    const size_t image_size = 10 * 1024 * 1024;
    const size_t partition_size = 15 * 1024 * 1024;
    base::FilePath system_path = GenerateImage("system.img", image_size);

    // Appends AVB Hashtree Footer.
    AddAvbFooter(system_path, "hashtree", "system", partition_size, "SHA512_RSA8192", 20,
                 data_dir_.Append("testkey_rsa8192.pem"), "d00df00d",
                 "--internal_release_string \"unit test\"");

    android::base::unique_fd fd(open(system_path.value().c_str(), O_RDONLY | O_CLOEXEC));
    ASSERT_TRUE(fd > 0);

    std::unique_ptr<AvbFooter> footer = GetAvbFooter(fd);
    EXPECT_TRUE(footer != nullptr);

    VBMetaVerifyResult verify_result;
    std::unique_ptr<VBMetaData> vbmeta =
            VerifyVBMetaData(fd, "system", "" /*expected_public_key_blob */, &verify_result);
    EXPECT_NE(nullptr, vbmeta);
    EXPECT_EQ(VBMetaVerifyResult::kSuccess, verify_result);

    // Modifies hash and signature, checks there is verification error.
    auto header = vbmeta->GetVBMetaHeader(true /* update_vbmeta_size */);
    size_t header_block_offset = 0;
    size_t authentication_block_offset = header_block_offset + sizeof(AvbVBMetaImageHeader);

    // Modifies the hash.
    ModifyFile(system_path,
               footer->vbmeta_offset + authentication_block_offset + header->hash_offset,
               header->hash_size);
    android::base::unique_fd hash_modified_fd(
            open(system_path.value().c_str(), O_RDONLY | O_CLOEXEC));
    ASSERT_TRUE(hash_modified_fd > 0);
    // Should return ErrorVerification.
    vbmeta = VerifyVBMetaData(hash_modified_fd, "system", "" /*expected_public_key_blob */,
                              &verify_result);
    EXPECT_NE(nullptr, vbmeta);
    EXPECT_TRUE(CompareVBMeta(system_path, *vbmeta));
    EXPECT_EQ(VBMetaVerifyResult::kErrorVerification, verify_result);

    // Modifies the auxiliary data block.
    size_t auxiliary_block_offset =
            authentication_block_offset + header->authentication_data_block_size;
    ModifyFile(system_path, footer->vbmeta_offset + auxiliary_block_offset,
               header->auxiliary_data_block_size);
    android::base::unique_fd aux_modified_fd(
            open(system_path.value().c_str(), O_RDONLY | O_CLOEXEC));
    ASSERT_TRUE(aux_modified_fd > 0);
    // Should return ErrorVerification.
    vbmeta = VerifyVBMetaData(aux_modified_fd, "system", "" /*expected_public_key_blob */,
                              &verify_result);
    EXPECT_NE(nullptr, vbmeta);
    EXPECT_TRUE(CompareVBMeta(system_path, *vbmeta));
    EXPECT_EQ(VBMetaVerifyResult::kErrorVerification, verify_result);

    // Resets previous modification by setting offset to -1, and checks the verification can pass.
    ModifyFile(system_path, 0 /* offset */, -1 /* length */);
    android::base::unique_fd ok_fd(open(system_path.value().c_str(), O_RDONLY | O_CLOEXEC));
    ASSERT_TRUE(ok_fd > 0);
    // Should return ResultOK..
    vbmeta = VerifyVBMetaData(ok_fd, "system", "" /*expected_public_key_blob */, &verify_result);
    EXPECT_NE(nullptr, vbmeta);
    EXPECT_TRUE(CompareVBMeta(system_path, *vbmeta));
    EXPECT_EQ(VBMetaVerifyResult::kSuccess, verify_result);
}

TEST_F(AvbUtilTest, GetChainPartitionInfo) {
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
    // Makes a vbmeta_system.img including the 'system' chained descriptor.
    GenerateVBMetaImage("vbmeta_system.img", "SHA256_RSA4096", 0,
                        data_dir_.Append("testkey_rsa4096.pem"),
                        {},                                  /* include_descriptor_image_paths */
                        {{"system", 3, rsa4096_public_key}}, /* chain_partitions */
                        "--internal_release_string \"unit test\"");

    // Makes a vbmeta image includeing 'boot' and 'vbmeta_system' chained descriptors.
    GenerateVBMetaImage("vbmeta.img", "SHA256_RSA8192", 0, data_dir_.Append("testkey_rsa8192.pem"),
                        {},                               /* include_descriptor_image_paths */
                        {{"boot", 1, rsa2048_public_key}, /* chain_partitions */
                         {"vbmeta_system", 2, rsa4096_public_key}},
                        "--internal_release_string \"unit test\"");

    // Calculates the digest of all chained partitions, to ensure the chained is formed properly.
    EXPECT_EQ("6f4bf815a651aa35ec7102a88b7906b91aef284bc5e20d0bf527c7d460da3266",
              CalcVBMetaDigest("vbmeta.img", "sha256"));
    // Loads the key blobs for comparison.
    std::string expected_key_blob_2048;
    EXPECT_TRUE(base::ReadFileToString(rsa2048_public_key, &expected_key_blob_2048));
    std::string expected_key_blob_4096;
    EXPECT_TRUE(base::ReadFileToString(rsa4096_public_key, &expected_key_blob_4096));

    // Checks chain descriptors in vbmeta.img
    EXPECT_EQ(
            "Minimum libavb version:   1.0\n"
            "Header Block:             256 bytes\n"
            "Authentication Block:     1088 bytes\n"
            "Auxiliary Block:          3840 bytes\n"
            "Algorithm:                SHA256_RSA8192\n"
            "Rollback Index:           0\n"
            "Flags:                    0\n"
            "Release String:           'unit test'\n"
            "Descriptors:\n"
            "    Chain Partition descriptor:\n"
            "      Partition Name:          boot\n"
            "      Rollback Index Location: 1\n"
            "      Public key (sha1):       cdbb77177f731920bbe0a0f94f84d9038ae0617d\n"
            "    Chain Partition descriptor:\n"
            "      Partition Name:          vbmeta_system\n"
            "      Rollback Index Location: 2\n"
            "      Public key (sha1):       2597c218aae470a130f61162feaae70afd97f011\n",
            InfoImage("vbmeta.img"));

    bool fatal_error = false;
    auto chained_descriptors = GetChainPartitionInfo(LoadVBMetaData("vbmeta.img"), &fatal_error);
    EXPECT_EQ(2, chained_descriptors.size());  // contains 'boot' and 'vbmeta_system'.
    EXPECT_EQ(false, fatal_error);

    EXPECT_EQ("boot", chained_descriptors[0].partition_name);
    EXPECT_EQ(expected_key_blob_2048, chained_descriptors[0].public_key_blob);

    EXPECT_EQ("vbmeta_system", chained_descriptors[1].partition_name);
    EXPECT_EQ(expected_key_blob_4096, chained_descriptors[1].public_key_blob);

    // Checks chain descriptors in vbmeta_system.img
    EXPECT_EQ(
            "Minimum libavb version:   1.0\n"
            "Header Block:             256 bytes\n"
            "Authentication Block:     576 bytes\n"
            "Auxiliary Block:          2176 bytes\n"
            "Algorithm:                SHA256_RSA4096\n"
            "Rollback Index:           0\n"
            "Flags:                    0\n"
            "Release String:           'unit test'\n"
            "Descriptors:\n"
            "    Chain Partition descriptor:\n"
            "      Partition Name:          system\n"
            "      Rollback Index Location: 3\n"
            "      Public key (sha1):       2597c218aae470a130f61162feaae70afd97f011\n",
            InfoImage("vbmeta_system.img"));

    chained_descriptors = GetChainPartitionInfo(LoadVBMetaData("vbmeta_system.img"), &fatal_error);
    EXPECT_EQ(1, chained_descriptors.size());  // contains 'system' only.
    EXPECT_EQ(false, fatal_error);
    EXPECT_EQ("system", chained_descriptors[0].partition_name);
    EXPECT_EQ(expected_key_blob_4096, chained_descriptors[0].public_key_blob);
}

TEST_F(AvbUtilTest, GetChainPartitionInfoNone) {
    // Generates a raw boot.img
    const size_t boot_image_size = 5 * 1024 * 1024;
    const size_t boot_partition_size = 10 * 1024 * 1024;
    base::FilePath boot_path = GenerateImage("boot.img", boot_image_size);
    // Adds AVB Hash Footer.
    AddAvbFooter(boot_path, "hash", "boot", boot_partition_size, "SHA256_RSA4096", 10,
                 data_dir_.Append("testkey_rsa4096.pem"), "d00df00d",
                 "--internal_release_string \"unit test\"");

    // Generates a raw system.img, use a smaller size to speed-up unit test.
    const size_t system_image_size = 10 * 1024 * 1024;
    const size_t system_partition_size = 15 * 1024 * 1024;
    base::FilePath system_path = GenerateImage("system.img", system_image_size);
    // Adds AVB Hashtree Footer.
    AddAvbFooter(system_path, "hashtree", "system", system_partition_size, "SHA512_RSA8192", 20,
                 data_dir_.Append("testkey_rsa8192.pem"), "d00df00d",
                 "--internal_release_string \"unit test\"");

    // Makes a vbmeta.img including both 'boot' and 'system' descriptors.
    GenerateVBMetaImage("vbmeta.img", "SHA256_RSA2048", 0, data_dir_.Append("testkey_rsa2048.pem"),
                        {boot_path, system_path}, /* include_descriptor_image_paths */
                        {},                       /* chain_partitions */
                        "--internal_release_string \"unit test\"");
    EXPECT_EQ("a069cbfc30c816cddf3b53f1ad53b7ca5d61a3d93845eb596bbb1b40caa1c62f",
              CalcVBMetaDigest("vbmeta.img", "sha256"));

    EXPECT_EQ(
            "Minimum libavb version:   1.0\n"
            "Header Block:             256 bytes\n"
            "Authentication Block:     320 bytes\n"
            "Auxiliary Block:          960 bytes\n"
            "Algorithm:                SHA256_RSA2048\n"
            "Rollback Index:           0\n"
            "Flags:                    0\n"
            "Release String:           'unit test'\n"
            "Descriptors:\n"
            "    Hash descriptor:\n"
            "      Image Size:            5242880 bytes\n"
            "      Hash Algorithm:        sha256\n"
            "      Partition Name:        boot\n"
            "      Salt:                  d00df00d\n"
            "      Digest:                "
            "222dd01e98284a1fcd7781f85d1392e43a530511a64eff96db197db90ebc4df1\n"
            "      Flags:                 0\n"
            "    Hashtree descriptor:\n"
            "      Version of dm-verity:  1\n"
            "      Image Size:            10485760 bytes\n"
            "      Tree Offset:           10485760\n"
            "      Tree Size:             86016 bytes\n"
            "      Data Block Size:       4096 bytes\n"
            "      Hash Block Size:       4096 bytes\n"
            "      FEC num roots:         2\n"
            "      FEC offset:            10571776\n"
            "      FEC size:              90112 bytes\n"
            "      Hash Algorithm:        sha1\n"
            "      Partition Name:        system\n"
            "      Salt:                  d00df00d\n"
            "      Root Digest:           a3d5dd307341393d85de356c384ff543ec1ed81b\n"
            "      Flags:                 0\n",
            InfoImage("vbmeta.img"));

    // Checks none of chain descriptors is found.
    bool fatal_error = false;
    auto chained_descriptors = GetChainPartitionInfo(LoadVBMetaData("vbmeta.img"), &fatal_error);
    EXPECT_EQ(0, chained_descriptors.size());  // There is no chain descriptors.
    EXPECT_EQ(false, fatal_error);
}

TEST_F(AvbUtilTest, LoadAndVerifyVbmetaByPath) {
    // Generates a raw system_other.img, use a smaller size to speed-up unit test.
    const size_t system_image_size = 10 * 1024 * 1024;
    const size_t system_partition_size = 15 * 1024 * 1024;
    base::FilePath system_path = GenerateImage("system_other.img", system_image_size);

    // Adds AVB Hashtree Footer.
    AddAvbFooter(system_path, "hashtree", "system_other", system_partition_size, "SHA512_RSA4096",
                 20, data_dir_.Append("testkey_rsa4096.pem"), "d00df00d",
                 "--internal_release_string \"unit test\"");

    base::FilePath rsa4096_public_key =
        ExtractPublicKeyAvb(data_dir_.Append("testkey_rsa4096.pem"));

    std::string expected_key_blob_4096;
    EXPECT_TRUE(base::ReadFileToString(rsa4096_public_key, &expected_key_blob_4096));

    bool verification_disabled;
    VBMetaVerifyResult verify_result;
    std::unique_ptr<VBMetaData> vbmeta = LoadAndVerifyVbmetaByPath(
        system_path.value(), "system_other", expected_key_blob_4096,
        false /* allow_verification_error */, false /* rollback_protection */,
        false /* is_chained_vbmeta */, &verification_disabled, &verify_result);

    EXPECT_NE(nullptr, vbmeta);
    EXPECT_EQ(VBMetaVerifyResult::kSuccess, verify_result);
    EXPECT_EQ(false, verification_disabled);

    EXPECT_EQ(2112UL, vbmeta->size());
    EXPECT_EQ(system_path.value(), vbmeta->vbmeta_path());
    EXPECT_EQ("system_other", vbmeta->partition());
    EXPECT_TRUE(CompareVBMeta(system_path, *vbmeta));
}

TEST_F(AvbUtilTest, LoadAndVerifyVbmetaByPathErrorVerification) {
    // Generates a raw system_other.img, use a smaller size to speed-up unit test.
    const size_t system_image_size = 10 * 1024 * 1024;
    const size_t system_partition_size = 15 * 1024 * 1024;
    base::FilePath system_path = GenerateImage("system_other.img", system_image_size);

    // Adds AVB Hashtree Footer.
    AddAvbFooter(system_path, "hashtree", "system_other", system_partition_size, "SHA512_RSA4096",
                 20, data_dir_.Append("testkey_rsa4096.pem"), "d00df00d",
                 "--internal_release_string \"unit test\"");

    base::FilePath rsa4096_public_key =
        ExtractPublicKeyAvb(data_dir_.Append("testkey_rsa4096.pem"));

    std::string expected_key_blob_4096;
    EXPECT_TRUE(base::ReadFileToString(rsa4096_public_key, &expected_key_blob_4096));

    // Modifies the auxiliary data of system_other.img
    auto fd = OpenUniqueReadFd(system_path);
    auto system_footer = GetAvbFooter(fd);
    auto system_vbmeta = ExtractAndLoadVBMetaData(system_path, "system_other-vbmeta.img");
    auto system_header = system_vbmeta.GetVBMetaHeader(true /* update_vbmeta_size */);
    size_t header_block_offset = 0;
    size_t authentication_block_offset = header_block_offset + sizeof(AvbVBMetaImageHeader);
    size_t auxiliary_block_offset =
        authentication_block_offset + system_header->authentication_data_block_size;

    // Modifies the hash.
    ModifyFile(
        system_path,
        (system_footer->vbmeta_offset + authentication_block_offset + system_header->hash_offset),
        system_header->hash_size);

    VBMetaVerifyResult verify_result;
    // Not allow verification error.
    std::unique_ptr<VBMetaData> vbmeta = LoadAndVerifyVbmetaByPath(
        system_path.value(), "system_other", expected_key_blob_4096,
        false /* allow_verification_error */, false /* rollback_protection */,
        false /* is_chained_vbmeta */, nullptr /* verification_disabled */, &verify_result);
    EXPECT_EQ(nullptr, vbmeta);

    // Allow verification error.
    vbmeta = LoadAndVerifyVbmetaByPath(
        system_path.value(), "system_other", expected_key_blob_4096,
        true /* allow_verification_error */, false /* rollback_protection */,
        false /* is_chained_vbmeta */, nullptr /* verification_disabled */, &verify_result);
    EXPECT_NE(nullptr, vbmeta);
    EXPECT_EQ(VBMetaVerifyResult::kErrorVerification, verify_result);

    EXPECT_EQ(2112UL, vbmeta->size());
    EXPECT_EQ(system_path.value(), vbmeta->vbmeta_path());
    EXPECT_EQ("system_other", vbmeta->partition());
    EXPECT_TRUE(CompareVBMeta(system_path, *vbmeta));

    // Modifies the auxiliary data block.
    ModifyFile(system_path, system_footer->vbmeta_offset + auxiliary_block_offset,
               system_header->auxiliary_data_block_size);

    // Not allow verification error.
    vbmeta = LoadAndVerifyVbmetaByPath(
        system_path.value(), "system_other", expected_key_blob_4096,
        false /* allow_verification_error */, false /* rollback_protection */,
        false /* is_chained_vbmeta */, nullptr /* verification_disabled */, &verify_result);
    EXPECT_EQ(nullptr, vbmeta);

    // Allow verification error.
    vbmeta = LoadAndVerifyVbmetaByPath(
        system_path.value(), "system_other", expected_key_blob_4096,
        true /* allow_verification_error */, false /* rollback_protection */,
        false /* is_chained_vbmeta */, nullptr /* verification_disabled */, &verify_result);
    EXPECT_NE(nullptr, vbmeta);
    EXPECT_EQ(VBMetaVerifyResult::kErrorVerification, verify_result);
}

TEST_F(AvbUtilTest, LoadAndVerifyVbmetaByPathUnexpectedPublicKey) {
    // Generates a raw system_other.img, use a smaller size to speed-up unit test.
    const size_t system_image_size = 10 * 1024 * 1024;
    const size_t system_partition_size = 15 * 1024 * 1024;
    base::FilePath system_path = GenerateImage("system_other.img", system_image_size);

    // Adds AVB Hashtree Footer.
    AddAvbFooter(system_path, "hashtree", "system_other", system_partition_size, "SHA512_RSA4096",
                 20, data_dir_.Append("testkey_rsa4096.pem"), "d00df00d",
                 "--internal_release_string \"unit test\"");

    base::FilePath rsa2048_public_key =
        ExtractPublicKeyAvb(data_dir_.Append("testkey_rsa2048.pem"));
    base::FilePath rsa4096_public_key =
        ExtractPublicKeyAvb(data_dir_.Append("testkey_rsa4096.pem"));

    std::string expected_key_blob_4096;
    EXPECT_TRUE(base::ReadFileToString(rsa4096_public_key, &expected_key_blob_4096));
    std::string unexpected_key_blob_2048;
    EXPECT_TRUE(base::ReadFileToString(rsa2048_public_key, &unexpected_key_blob_2048));

    // Uses the correct expected public key.
    VBMetaVerifyResult verify_result;
    std::unique_ptr<VBMetaData> vbmeta = LoadAndVerifyVbmetaByPath(
        system_path.value(), "system_other", expected_key_blob_4096,
        false /* allow_verification_error */, false /* rollback_protection */,
        false /* is_chained_vbmeta */, nullptr /* verification_disabled */, &verify_result);
    EXPECT_NE(nullptr, vbmeta);
    EXPECT_EQ(verify_result, VBMetaVerifyResult::kSuccess);
    EXPECT_EQ(2112UL, vbmeta->size());
    EXPECT_EQ(system_path.value(), vbmeta->vbmeta_path());
    EXPECT_EQ("system_other", vbmeta->partition());
    EXPECT_TRUE(CompareVBMeta(system_path, *vbmeta));

    // Uses the wrong expected public key with allow_verification_error set to false.
    vbmeta = LoadAndVerifyVbmetaByPath(
        system_path.value(), "system_other", unexpected_key_blob_2048,
        false /* allow_verification_error */, false /* rollback_protection */,
        false /* is_chained_vbmeta */, nullptr /* verification_disabled */, &verify_result);
    EXPECT_EQ(nullptr, vbmeta);

    // Uses the wrong expected public key with allow_verification_error set to true.
    vbmeta = LoadAndVerifyVbmetaByPath(
        system_path.value(), "system_other", unexpected_key_blob_2048,
        true /* allow_verification_error */, false /* rollback_protection */,
        false /* is_chained_vbmeta */, nullptr /* verification_disabled */, &verify_result);
    EXPECT_NE(nullptr, vbmeta);
    EXPECT_EQ(verify_result, VBMetaVerifyResult::kErrorVerification);
    EXPECT_EQ(2112UL, vbmeta->size());
    EXPECT_EQ(system_path.value(), vbmeta->vbmeta_path());
    EXPECT_EQ("system_other", vbmeta->partition());
    EXPECT_TRUE(CompareVBMeta(system_path, *vbmeta));
}

TEST_F(AvbUtilTest, LoadAndVerifyVbmetaByPathVerificationDisabled) {
    // Generates a raw system_other.img, use a smaller size to speed-up unit test.
    const size_t system_image_size = 10 * 1024 * 1024;
    const size_t system_partition_size = 15 * 1024 * 1024;
    base::FilePath system_path = GenerateImage("system_other.img", system_image_size);

    // Adds AVB Hashtree Footer.
    AddAvbFooter(system_path, "hashtree", "system_other", system_partition_size, "SHA512_RSA4096",
                 20, data_dir_.Append("testkey_rsa4096.pem"), "d00df00d",
                 "--internal_release_string \"unit test\"");

    base::FilePath rsa4096_public_key =
        ExtractPublicKeyAvb(data_dir_.Append("testkey_rsa4096.pem"));

    std::string expected_key_blob_4096;
    EXPECT_TRUE(base::ReadFileToString(rsa4096_public_key, &expected_key_blob_4096));

    // Sets disabled flag and expect the returned verification_disabled is true.
    SetVBMetaFlags(system_path, AVB_VBMETA_IMAGE_FLAGS_VERIFICATION_DISABLED);
    bool verification_disabled;
    VBMetaVerifyResult verify_result;
    std::unique_ptr<VBMetaData> vbmeta = LoadAndVerifyVbmetaByPath(
        system_path.value(), "system_other", expected_key_blob_4096,
        true /* allow_verification_error */, false /* rollback_protection */,
        false /* is_chained_vbmeta */, &verification_disabled, &verify_result);

    EXPECT_NE(nullptr, vbmeta);
    EXPECT_EQ(VBMetaVerifyResult::kErrorVerification, verify_result);
    EXPECT_EQ(true, verification_disabled);  // should be true.

    EXPECT_EQ(2112UL, vbmeta->size());
    EXPECT_EQ(system_path.value(), vbmeta->vbmeta_path());
    EXPECT_EQ("system_other", vbmeta->partition());
    EXPECT_TRUE(CompareVBMeta(system_path, *vbmeta));

    // Since the vbmeta flags is modified, vbmeta will be nullptr
    // if verification error isn't allowed.
    vbmeta = LoadAndVerifyVbmetaByPath(
        system_path.value(), "system_other", expected_key_blob_4096,
        false /* allow_verification_error */, false /* rollback_protection */,
        false /* is_chained_vbmeta */, &verification_disabled, &verify_result);
    EXPECT_EQ(nullptr, vbmeta);
}

TEST_F(AvbUtilTest, LoadAndVerifyVbmetaByPartition) {
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
    // Makes a vbmeta_system.img including the 'system' chained descriptor.
    auto vbmeta_system_path = GenerateVBMetaImage(
            "vbmeta_system.img", "SHA256_RSA4096", 0, data_dir_.Append("testkey_rsa4096.pem"),
            {},                                  /* include_descriptor_image_paths */
            {{"system", 3, rsa4096_public_key}}, /* chain_partitions */
            "--internal_release_string \"unit test\"");

    // Makes a vbmeta image includeing 'boot' and 'vbmeta_system' chained descriptors.
    auto vbmeta_path = GenerateVBMetaImage("vbmeta.img", "SHA256_RSA8192", 0,
                                           data_dir_.Append("testkey_rsa8192.pem"),
                                           {}, /* include_descriptor_image_paths */
                                           {{"boot", 1, rsa2048_public_key}, /* chain_partitions */
                                            {"vbmeta_system", 2, rsa4096_public_key}},
                                           "--internal_release_string \"unit test\"");

    // Calculates the digest of all chained partitions, to ensure the chained is formed properly.
    EXPECT_EQ("6f4bf815a651aa35ec7102a88b7906b91aef284bc5e20d0bf527c7d460da3266",
              CalcVBMetaDigest("vbmeta.img", "sha256"));

    // Starts to test LoadAndVerifyVbmetaByPartition.
    std::vector<VBMetaData> vbmeta_images;
    auto vbmeta_image_path = [this](const std::string& partition_name) {
        return test_dir_.Append(partition_name + ".img").value();
    };

    EXPECT_EQ(VBMetaVerifyResult::kSuccess,
              LoadAndVerifyVbmetaByPartition(
                  "vbmeta" /* partition_name */, "" /* ab_suffix */, "" /* other_suffix */,
                  "" /* expected_public_key_blob*/, false /* allow_verification_error */,
                  true /* load_chained_vbmeta */, true /* rollback_protection */, vbmeta_image_path,
                  false /* is_chained_vbmeta*/, &vbmeta_images));

    EXPECT_EQ(4UL, vbmeta_images.size());  // vbmeta, boot, vbmeta_system and system
    // Binary comparison for each vbmeta image.
    EXPECT_TRUE(CompareVBMeta(vbmeta_path, vbmeta_images[0]));
    EXPECT_TRUE(CompareVBMeta(boot_path, vbmeta_images[1]));
    EXPECT_TRUE(CompareVBMeta(vbmeta_system_path, vbmeta_images[2]));
    EXPECT_TRUE(CompareVBMeta(system_path, vbmeta_images[3]));

    // Skip loading chained vbmeta images.
    vbmeta_images.clear();
    EXPECT_EQ(VBMetaVerifyResult::kSuccess,
              LoadAndVerifyVbmetaByPartition(
                  "vbmeta" /* partition_name */, "" /* ab_suffix */, "" /* other_suffix */,
                  "" /* expected_public_key_blob*/, false /* allow_verification_error */,
                  false /* load_chained_vbmeta */, true /* rollback_protection */,
                  vbmeta_image_path, false /* is_chained_vbmeta*/, &vbmeta_images));
    // Only vbmeta is loaded.
    EXPECT_EQ(1UL, vbmeta_images.size());
    EXPECT_TRUE(CompareVBMeta(vbmeta_path, vbmeta_images[0]));
}

TEST_F(AvbUtilTest, LoadAndVerifyVbmetaByPartitionWithSuffixes) {
    // Tests the following chained partitions.
    // vbmeta_a.img
    // |--> boot_b.img (boot_other)
    // |--> vbmeta_system_b.img (vbmeta_system_other)
    //      |--> system_a.img

    // Generates a raw boot_b.img
    const size_t boot_image_size = 5 * 1024 * 1024;
    const size_t boot_partition_size = 10 * 1024 * 1024;
    base::FilePath boot_path = GenerateImage("boot_b.img", boot_image_size);

    // Adds AVB Hash Footer.
    AddAvbFooter(boot_path, "hash", "boot", boot_partition_size, "SHA256_RSA2048", 10,
                 data_dir_.Append("testkey_rsa2048.pem"), "d00df00d",
                 "--internal_release_string \"unit test\"");

    // Generates a raw system_a.img, use a smaller size to speed-up unit test.
    const size_t system_image_size = 10 * 1024 * 1024;
    const size_t system_partition_size = 15 * 1024 * 1024;
    base::FilePath system_path = GenerateImage("system_a.img", system_image_size);
    // Adds AVB Hashtree Footer.
    AddAvbFooter(system_path, "hashtree", "system", system_partition_size, "SHA512_RSA4096", 20,
                 data_dir_.Append("testkey_rsa4096.pem"), "d00df00d",
                 "--internal_release_string \"unit test\"");

    // Generates chain partition descriptors.
    base::FilePath rsa2048_public_key =
            ExtractPublicKeyAvb(data_dir_.Append("testkey_rsa2048.pem"));
    base::FilePath rsa4096_public_key =
            ExtractPublicKeyAvb(data_dir_.Append("testkey_rsa4096.pem"));
    // Makes a vbmeta_system_b.img including the 'system' chained descriptor.
    auto vbmeta_system_path = GenerateVBMetaImage(
            "vbmeta_system_b.img", "SHA256_RSA4096", 0, data_dir_.Append("testkey_rsa4096.pem"),
            {},                                  /* include_descriptor_image_paths */
            {{"system", 3, rsa4096_public_key}}, /* chain_partitions */
            "--internal_release_string \"unit test\"");

    // Makes a vbmeta_a.img includeing 'boot_other' and 'vbmeta_system_other' chained descriptors.
    auto vbmeta_path = GenerateVBMetaImage(
            "vbmeta_a.img", "SHA256_RSA8192", 0, data_dir_.Append("testkey_rsa8192.pem"),
            {},                                     /* include_descriptor_image_paths */
            {{"boot_other", 1, rsa2048_public_key}, /* chain_partitions */
             {"vbmeta_system_other", 2, rsa4096_public_key}},
            "--internal_release_string \"unit test\"");

    // Starts to test LoadAndVerifyVbmetaByPartition with ab_suffix and ab_other_suffix.
    auto vbmeta_image_path = [this](const std::string& partition_name) {
        return test_dir_.Append(partition_name + ".img").value();
    };

    std::vector<VBMetaData> vbmeta_images;
    EXPECT_EQ(VBMetaVerifyResult::kSuccess,
              LoadAndVerifyVbmetaByPartition(
                  "vbmeta" /* partition_name */, "_a" /* ab_suffix */, "_b" /* other_suffix */,
                  "" /* expected_public_key_blob*/, false /* allow_verification_error */,
                  true /* load_chained_vbmeta */, true /* rollback_protection */, vbmeta_image_path,
                  false /* is_chained_vbmeta*/, &vbmeta_images));

    EXPECT_EQ(4UL, vbmeta_images.size());  // vbmeta, boot_other, vbmeta_system_other and system
    // Binary comparison for each vbmeta image.
    EXPECT_TRUE(CompareVBMeta(vbmeta_path, vbmeta_images[0]));
    EXPECT_TRUE(CompareVBMeta(boot_path, vbmeta_images[1]));
    EXPECT_TRUE(CompareVBMeta(vbmeta_system_path, vbmeta_images[2]));
    EXPECT_TRUE(CompareVBMeta(system_path, vbmeta_images[3]));

    // Skips loading chained vbmeta images.
    vbmeta_images.clear();
    EXPECT_EQ(VBMetaVerifyResult::kSuccess,
              LoadAndVerifyVbmetaByPartition(
                  "vbmeta" /* partition_name */, "_a" /* ab_suffix */, "_b" /* other_suffix */,
                  "" /* expected_public_key_blob*/, false /* allow_verification_error */,
                  false /* load_chained_vbmeta */, true /* rollback_protection */,
                  vbmeta_image_path, false /* is_chained_vbmeta*/, &vbmeta_images));
    // Only vbmeta is loaded.
    EXPECT_EQ(1UL, vbmeta_images.size());
    EXPECT_TRUE(CompareVBMeta(vbmeta_path, vbmeta_images[0]));

    // Using an invalid suffix for 'other' slot, checks it returns error.
    EXPECT_EQ(VBMetaVerifyResult::kError,
              LoadAndVerifyVbmetaByPartition(
                  "vbmeta" /* partition_name */, "_a" /* ab_suffix */,
                  "_invalid_suffix" /* other_suffix */, "" /* expected_public_key_blob*/,
                  false /* allow_verification_error */, true /* load_chained_vbmeta */,
                  true /* rollback_protection */, vbmeta_image_path, false /* is_chained_vbmeta*/,
                  &vbmeta_images));
}

TEST_F(AvbUtilTest, LoadAndVerifyVbmetaByPartitionErrorVerification) {
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

    // Makes a vbmeta image includeing 'boot' and 'vbmeta_system' chained descriptors.
    auto vbmeta_path = GenerateVBMetaImage("vbmeta.img", "SHA256_RSA8192", 0,
                                           data_dir_.Append("testkey_rsa8192.pem"),
                                           {}, /* include_descriptor_image_paths */
                                           {{"boot", 1, rsa2048_public_key}, /* chain_partitions */
                                            {"system", 2, rsa4096_public_key}},
                                           "--internal_release_string \"unit test\"");

    // Calculates the digest of all chained partitions, to ensure the chained is formed properly.
    EXPECT_EQ("abbe11b316901f3336e26630f64c4732dadbe14532186ac8640e4141a403721f",
              CalcVBMetaDigest("vbmeta.img", "sha256"));

    auto vbmeta = LoadVBMetaData("vbmeta.img");

    // Modifies hash, checks there is error if allow_verification_error is false.
    auto header = vbmeta.GetVBMetaHeader(true /* update_vbmeta_size */);
    size_t header_block_offset = 0;
    size_t authentication_block_offset = header_block_offset + sizeof(AvbVBMetaImageHeader);

    // Modifies the hash.
    ModifyFile(vbmeta_path, authentication_block_offset + header->hash_offset, header->hash_size);

    // Starts to test LoadAndVerifyVbmetaByPartition.
    std::vector<VBMetaData> vbmeta_images;
    auto vbmeta_image_path = [this](const std::string& partition_name) {
        return test_dir_.Append(partition_name + ".img").value();
    };
    EXPECT_EQ(VBMetaVerifyResult::kError,
              LoadAndVerifyVbmetaByPartition(
                  "vbmeta" /* partition_name */, "" /* ab_suffix */, "" /* other_suffix */,
                  "" /* expected_public_key_blob*/, false /* allow_verification_error */,
                  true /* load_chained_vbmeta */, true /* rollback_protection */, vbmeta_image_path,
                  false /* is_chained_vbmeta*/, &vbmeta_images));
    // Stops to load vbmeta because the top-level vbmeta has verification error.
    EXPECT_EQ(0UL, vbmeta_images.size());

    // Tries again with verification error allowed.
    EXPECT_EQ(VBMetaVerifyResult::kErrorVerification,
              LoadAndVerifyVbmetaByPartition(
                  "vbmeta" /* partition_name */, "" /* ab_suffix */, "", /* other_suffix */
                  "" /* expected_public_key_blob*/, true /* allow_verification_error */,
                  true /* load_chained_vbmeta */, true /* rollback_protection */, vbmeta_image_path,
                  false /* is_chained_vbmeta*/, &vbmeta_images));

    EXPECT_EQ(3UL, vbmeta_images.size());  // vbmeta, boot, and system
    // Binary comparison for each vbmeta image.
    EXPECT_TRUE(CompareVBMeta(vbmeta_path, vbmeta_images[0]));
    EXPECT_TRUE(CompareVBMeta(boot_path, vbmeta_images[1]));
    EXPECT_TRUE(CompareVBMeta(system_path, vbmeta_images[2]));

    // Resets the modification of the hash.
    ModifyFile(vbmeta_path, 0 /* offset */, -1 /* length */);

    // Modifies the auxiliary data of system.img
    auto fd = OpenUniqueReadFd(system_path);
    auto system_footer = GetAvbFooter(fd);
    auto system_vbmeta = ExtractAndLoadVBMetaData(system_path, "system-vbmeta.img");
    auto system_header = system_vbmeta.GetVBMetaHeader(true /* update_vbmeta_size */);
    size_t auxiliary_block_offset =
            authentication_block_offset + system_header->authentication_data_block_size;

    // Modifies the auxiliary data block.
    ModifyFile(system_path, system_footer->vbmeta_offset + auxiliary_block_offset,
               system_header->auxiliary_data_block_size);
    vbmeta_images.clear();
    EXPECT_EQ(VBMetaVerifyResult::kError,
              LoadAndVerifyVbmetaByPartition(
                  "vbmeta" /* partition_name */, "" /* ab_suffix */, "" /* other_suffix */,
                  "" /* expected_public_key_blob*/, false /* allow_verification_error */,
                  true /* load_chained_vbmeta */, true /* rollback_protection */, vbmeta_image_path,
                  false /* is_chained_vbmeta*/, &vbmeta_images));
    // 'vbmeta', 'boot' but no 'system', because of verification error.
    EXPECT_EQ(2UL, vbmeta_images.size());
    // Binary comparison for the loaded 'vbmeta' and 'boot'.
    EXPECT_TRUE(CompareVBMeta(vbmeta_path, vbmeta_images[0]));
    EXPECT_TRUE(CompareVBMeta(boot_path, vbmeta_images[1]));

    // Resets the modification of the auxiliary data.
    ModifyFile(system_path, 0 /* offset */, -1 /* length */);

    // Sets the vbmeta header flags on a chained partition, which introduces an error.
    ModifyFile(system_path, system_footer->vbmeta_offset + offsetof(AvbVBMetaImageHeader, flags),
               sizeof(uint32_t));
    EXPECT_EQ(VBMetaVerifyResult::kError,
              LoadAndVerifyVbmetaByPartition(
                  "vbmeta" /* partition_name */, "" /* ab_suffix */, "" /* other_suffix */,
                  "" /* expected_public_key_blob*/, true /* allow_verification_error */,
                  true /* load_chained_vbmeta */, true /* rollback_protection */, vbmeta_image_path,
                  false /* is_chained_vbmeta*/, &vbmeta_images));
}

TEST_F(AvbUtilTest, LoadAndVerifyVbmetaByPartitionVerificationDisabled) {
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
    // Makes a vbmeta_system.img including the 'system' chained descriptor.
    auto vbmeta_system_path = GenerateVBMetaImage(
        "vbmeta_system.img", "SHA256_RSA4096", 0, data_dir_.Append("testkey_rsa4096.pem"),
        {},                                  /* include_descriptor_image_paths */
        {{"system", 3, rsa4096_public_key}}, /* chain_partitions */
        "--internal_release_string \"unit test\"");

    // Makes a vbmeta image includeing 'boot' and 'vbmeta_system' chained descriptors.
    auto vbmeta_path = GenerateVBMetaImage("vbmeta.img", "SHA256_RSA8192", 0,
                                           data_dir_.Append("testkey_rsa8192.pem"),
                                           {}, /* include_descriptor_image_paths */
                                           {{"boot", 1, rsa2048_public_key}, /* chain_partitions */
                                            {"vbmeta_system", 2, rsa4096_public_key}},
                                           "--internal_release_string \"unit test\"");

    // Calculates the digest of all chained partitions, to ensure the chained is formed properly.
    EXPECT_EQ("6f4bf815a651aa35ec7102a88b7906b91aef284bc5e20d0bf527c7d460da3266",
              CalcVBMetaDigest("vbmeta.img", "sha256"));

    // Starts to test LoadAndVerifyVbmetaByPartition.
    std::vector<VBMetaData> vbmeta_images;
    auto vbmeta_image_path = [this](const std::string& partition_name) {
        return test_dir_.Append(partition_name + ".img").value();
    };

    EXPECT_EQ(VBMetaVerifyResult::kSuccess,
              LoadAndVerifyVbmetaByPartition(
                  "vbmeta" /* partition_name */, "" /* ab_suffix */, "" /* other_suffix */,
                  "" /* expected_public_key_blob*/, false /* allow_verification_error */,
                  true /* load_chained_vbmeta */, true /* rollback_protection */, vbmeta_image_path,
                  false /* is_chained_vbmeta*/, &vbmeta_images));

    EXPECT_EQ(4UL, vbmeta_images.size());  // vbmeta, boot, vbmeta_system and system
    // Binary comparison for each vbmeta image.
    EXPECT_TRUE(CompareVBMeta(vbmeta_path, vbmeta_images[0]));
    EXPECT_TRUE(CompareVBMeta(boot_path, vbmeta_images[1]));
    EXPECT_TRUE(CompareVBMeta(vbmeta_system_path, vbmeta_images[2]));
    EXPECT_TRUE(CompareVBMeta(system_path, vbmeta_images[3]));

    // Sets VERIFICATION_DISABLED to the top-level vbmeta.img
    SetVBMetaFlags(vbmeta_path, AVB_VBMETA_IMAGE_FLAGS_VERIFICATION_DISABLED);
    vbmeta_images.clear();
    EXPECT_EQ(VBMetaVerifyResult::kErrorVerification,
              LoadAndVerifyVbmetaByPartition(
                  "vbmeta" /* partition_name */, "" /* ab_suffix */, "" /* other_suffix */,
                  "" /* expected_public_key_blob*/, true /* allow_verification_error */,
                  true /* load_chained_vbmeta */, true /* rollback_protection */, vbmeta_image_path,
                  false /* is_chained_vbmeta*/, &vbmeta_images));
    EXPECT_EQ(1UL, vbmeta_images.size());  // Only vbmeta is loaded
    EXPECT_TRUE(CompareVBMeta(vbmeta_path, vbmeta_images[0]));

    // HASHTREE_DISABLED still loads the chained vbmeta.
    SetVBMetaFlags(vbmeta_path, AVB_VBMETA_IMAGE_FLAGS_HASHTREE_DISABLED);
    vbmeta_images.clear();
    EXPECT_EQ(VBMetaVerifyResult::kErrorVerification,
              LoadAndVerifyVbmetaByPartition(
                  "vbmeta" /* partition_name */, "" /* ab_suffix */, "" /* other_suffix */,
                  "" /* expected_public_key_blob*/, true /* allow_verification_error */,
                  true /* load_chained_vbmeta */, true /* rollback_protection */, vbmeta_image_path,
                  false /* is_chained_vbmeta*/, &vbmeta_images));
    EXPECT_EQ(4UL, vbmeta_images.size());  // vbmeta, boot, vbmeta_system and system
    // Binary comparison for each vbmeta image.
    EXPECT_TRUE(CompareVBMeta(vbmeta_path, vbmeta_images[0]));
    EXPECT_TRUE(CompareVBMeta(boot_path, vbmeta_images[1]));
    EXPECT_TRUE(CompareVBMeta(vbmeta_system_path, vbmeta_images[2]));
    EXPECT_TRUE(CompareVBMeta(system_path, vbmeta_images[3]));
}

TEST_F(AvbUtilTest, LoadAndVerifyVbmetaByPartitionUnexpectedPublicKey) {
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
    std::string expected_key_blob_4096;
    EXPECT_TRUE(base::ReadFileToString(rsa4096_public_key, &expected_key_blob_4096));
    std::string expected_key_blob_8192;
    EXPECT_TRUE(base::ReadFileToString(rsa8192_public_key, &expected_key_blob_8192));

    auto vbmeta_image_path = [this](const std::string& partition_name) {
        return test_dir_.Append(partition_name + ".img").value();
    };
    std::vector<VBMetaData> vbmeta_images;
    // Uses the correct expected public key.
    EXPECT_EQ(VBMetaVerifyResult::kSuccess,
              LoadAndVerifyVbmetaByPartition(
                  "vbmeta" /* partition_name */, "" /* ab_suffix */, "" /* other_suffix */,
                  expected_key_blob_8192, true /* allow_verification_error */,
                  false /* load_chained_vbmeta */, true /* rollback_protection */,
                  vbmeta_image_path, false /* is_chained_vbmeta*/, &vbmeta_images));

    // Uses the wrong expected public key with allow_verification_error set to true.
    vbmeta_images.clear();
    EXPECT_EQ(VBMetaVerifyResult::kErrorVerification,
              LoadAndVerifyVbmetaByPartition(
                  "vbmeta" /* partition_name */, "" /* ab_suffix */, "" /* other_suffix */,
                  expected_key_blob_4096, true /* allow_verification_error */,
                  false /* load_chained_vbmeta */, true /* rollback_protection */,
                  vbmeta_image_path, false /* is_chained_vbmeta*/, &vbmeta_images));

    // Uses the wrong expected public key with allow_verification_error set to false.
    vbmeta_images.clear();
    EXPECT_EQ(VBMetaVerifyResult::kError,
              LoadAndVerifyVbmetaByPartition(
                  "vbmeta" /* partition_name */, "" /* ab_suffix */, "" /* other_suffix */,
                  expected_key_blob_4096, false /* allow_verification_error */,
                  false /* load_chained_vbmeta */, true /* rollback_protection */,
                  vbmeta_image_path, false /* is_chained_vbmeta*/, &vbmeta_images));
}

}  // namespace fs_avb_host_test

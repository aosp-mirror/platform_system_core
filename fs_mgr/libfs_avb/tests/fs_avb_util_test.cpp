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

#include <fs_avb/fs_avb_util.h>

#include "fs_avb_test_util.h"

namespace fs_avb_host_test {

class PublicFsAvbUtilTest : public BaseFsAvbTest {
  public:
    PublicFsAvbUtilTest(){};

  protected:
    ~PublicFsAvbUtilTest(){};
};

TEST_F(PublicFsAvbUtilTest, GetHashtreeDescriptor) {
    // Generates a raw system_other.img, use a smaller size to speed-up unit test.
    const size_t system_image_size = 10 * 1024 * 1024;
    const size_t system_partition_size = 15 * 1024 * 1024;
    base::FilePath system_path = GenerateImage("system.img", system_image_size);

    // Adds AVB Hashtree Footer.
    AddAvbFooter(system_path, "hashtree", "system", system_partition_size, "SHA512_RSA4096", 20,
                 data_dir_.Append("testkey_rsa4096.pem"), "d00df00d",
                 "--internal_release_string \"unit test\"");

    auto system_vbmeta = ExtractAndLoadVBMetaData(system_path, "system-vbmeta.img");

    auto hashtree_desc =
            GetHashtreeDescriptor("system" /* avb_partition_name */, std::move(system_vbmeta));
    EXPECT_NE(nullptr, hashtree_desc);

    // Checks the returned hashtree_desc matches the following info returned by avbtool.
    EXPECT_EQ(
            "Footer version:           1.0\n"
            "Image size:               15728640 bytes\n"
            "Original image size:      10485760 bytes\n"
            "VBMeta offset:            10661888\n"
            "VBMeta size:              2112 bytes\n"
            "--\n"
            "Minimum libavb version:   1.0\n"
            "Header Block:             256 bytes\n"
            "Authentication Block:     576 bytes\n"
            "Auxiliary Block:          1280 bytes\n"
            "Algorithm:                SHA512_RSA4096\n"
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

    EXPECT_EQ(1UL, hashtree_desc->dm_verity_version);
    EXPECT_EQ(10485760UL, hashtree_desc->image_size);
    EXPECT_EQ(10485760UL, hashtree_desc->tree_offset);
    EXPECT_EQ(86016UL, hashtree_desc->tree_size);
    EXPECT_EQ(4096UL, hashtree_desc->data_block_size);
    EXPECT_EQ(4096UL, hashtree_desc->hash_block_size);
    EXPECT_EQ(2UL, hashtree_desc->fec_num_roots);
    EXPECT_EQ(10571776UL, hashtree_desc->fec_offset);
    EXPECT_EQ(90112UL, hashtree_desc->fec_size);
    EXPECT_EQ(std::string("sha1"),
              std::string(reinterpret_cast<const char*>(hashtree_desc->hash_algorithm)));
    EXPECT_EQ(std::string("system").length(), hashtree_desc->partition_name_len);
    EXPECT_EQ(hashtree_desc->partition_name, "system");
    EXPECT_EQ(hashtree_desc->salt, "d00df00d");
    EXPECT_EQ(hashtree_desc->root_digest, "a3d5dd307341393d85de356c384ff543ec1ed81b");

    // Checks it's null if partition name doesn't match.
    EXPECT_EQ(nullptr, GetHashtreeDescriptor("system_not_exist" /* avb_partition_name */,
                                             std::move(system_vbmeta)));
}

TEST_F(PublicFsAvbUtilTest, GetHashtreeDescriptor_NotFound) {
    // Generates a raw boot.img
    const size_t image_size = 5 * 1024 * 1024;
    const size_t partition_size = 10 * 1024 * 1024;
    base::FilePath boot_path = GenerateImage("boot.img", image_size);
    // Appends AVB Hash Footer.
    AddAvbFooter(boot_path, "hash", "boot", partition_size, "SHA256_RSA4096", 10,
                 data_dir_.Append("testkey_rsa4096.pem"), "d00df00d",
                 "--internal_release_string \"unit test\"");
    // Extracts boot vbmeta from boot.img into boot-vbmeta.img.
    auto boot_vbmeta = ExtractAndLoadVBMetaData(boot_path, "boot-vbmeta.img");

    auto hashtree_desc =
            GetHashtreeDescriptor("boot" /* avb_partition_name */, std::move(boot_vbmeta));
    EXPECT_EQ(nullptr, hashtree_desc);
}

}  // namespace fs_avb_host_test

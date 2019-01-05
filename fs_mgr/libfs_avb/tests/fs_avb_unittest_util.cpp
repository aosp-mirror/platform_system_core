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

#include "fs_avb_unittest_util.h"

#include <stdlib.h>

#include <android-base/file.h>
#include <base/files/file_util.h>
#include <base/strings/string_util.h>

namespace fs_avb_host_test {

void BaseFsAvbTest::SetUp() {
    // Changes current directory to test executable directory so that relative path
    // references to test dependencies don't rely on being manually run from
    // the executable directory. With this, we can just open "./data/testkey_rsa2048.pem"
    // from the source.
    base::SetCurrentDirectory(base::FilePath(android::base::GetExecutableDirectory()));

    // Creates a temporary directory, e.g., /tmp/libfs_avb-tests.XXXXXX to stash images in.
    base::FilePath tmp_dir;
    ASSERT_TRUE(GetTempDir(&tmp_dir));
    base::CreateTemporaryDirInDir(tmp_dir, "libfs_avb-tests.", &test_dir_);
}

void BaseFsAvbTest::TearDown() {
    // Nukes temporary directory.
    ASSERT_NE(std::string::npos, test_dir_.value().find("libfs_avb-tests"));
    ASSERT_TRUE(base::DeleteFile(test_dir_, true /* recursive */));
}

std::string BaseFsAvbTest::CalcVBMetaDigest(const std::string& file_name,
                                            const std::string& hash_algorithm) {
    auto iter = vbmeta_images_.find(file_name);
    EXPECT_NE(iter, vbmeta_images_.end());  // ensures file_name is generated before.

    // Gets the image path from iterator->second.path: VBMetaImage.path.
    base::FilePath image_path = iter->second.path;
    base::FilePath vbmeta_digest_path = test_dir_.Append("vbmeta_digest");
    EXPECT_COMMAND(0,
                   "avbtool calculate_vbmeta_digest --image %s --hash_algorithm %s"
                   " --output %s",
                   image_path.value().c_str(), hash_algorithm.c_str(),
                   vbmeta_digest_path.value().c_str());
    // Reads the content of the output digest file.
    std::string vbmeta_digest_data;
    EXPECT_TRUE(base::ReadFileToString(vbmeta_digest_path, &vbmeta_digest_data));
    // Returns the trimmed digest.
    std::string trimmed_digest_data;
    base::TrimString(vbmeta_digest_data, " \t\n", &trimmed_digest_data);
    return trimmed_digest_data;
}

void BaseFsAvbTest::GenerateVBMetaImage(
        const std::string& file_name, const std::string& avb_algorithm, uint64_t rollback_index,
        const base::FilePath& key_path,
        const std::vector<base::FilePath>& include_descriptor_image_paths,
        const std::vector<ChainPartitionConfig>& chain_partitions,
        const std::string& additional_options) {
    // --algorithm and --key
    std::string signing_options;
    if (avb_algorithm == "") {
        signing_options = " --algorithm NONE ";
    } else {
        signing_options =
                std::string(" --algorithm ") + avb_algorithm + " --key " + key_path.value() + " ";
    }
    // --include_descriptors_from_image
    std::string include_descriptor_options;
    for (const auto& path : include_descriptor_image_paths) {
        include_descriptor_options += " --include_descriptors_from_image " + path.value();
    }
    // --chain_partitions
    std::string chain_partition_options;
    for (const auto& partition : chain_partitions) {
        chain_partition_options += base::StringPrintf(
                " --chain_partition %s:%u:%s", partition.partition_name.c_str(),
                partition.rollback_index_location, partition.key_blob_path.value().c_str());
    }
    // Starts to 'make_vbmeta_image'.
    VBMetaImage vbmeta_image;
    vbmeta_image.path = test_dir_.Append(file_name);
    EXPECT_COMMAND(0,
                   "avbtool make_vbmeta_image"
                   " --rollback_index %" PRIu64
                   " %s %s %s %s"
                   " --output %s",
                   rollback_index, signing_options.c_str(), include_descriptor_options.c_str(),
                   chain_partition_options.c_str(), additional_options.c_str(),
                   vbmeta_image.path.value().c_str());
    int64_t file_size;
    ASSERT_TRUE(base::GetFileSize(vbmeta_image.path, &file_size));
    vbmeta_image.content.resize(file_size);
    ASSERT_TRUE(base::ReadFile(vbmeta_image.path,
                               reinterpret_cast<char*>(vbmeta_image.content.data()), file_size));
    // Stores the generated vbmeta image into vbmeta_images_ member object.
    vbmeta_images_.emplace(file_name, std::move(vbmeta_image));
}

void BaseFsAvbTest::ExtractVBMetaImage(const base::FilePath& image_path,
                                       const std::string& output_file_name,
                                       const size_t padding_size) {
    VBMetaImage vbmeta_image;
    vbmeta_image.path = test_dir_.Append(output_file_name);
    EXPECT_COMMAND(0,
                   "avbtool extract_vbmeta_image"
                   " --image %s"
                   " --output %s"
                   " --padding_size %zu",
                   image_path.value().c_str(), vbmeta_image.path.value().c_str(), padding_size);
    int64_t file_size;
    ASSERT_TRUE(base::GetFileSize(vbmeta_image.path, &file_size));
    vbmeta_image.content.resize(file_size);
    ASSERT_TRUE(base::ReadFile(vbmeta_image.path,
                               reinterpret_cast<char*>(vbmeta_image.content.data()), file_size));
    // Stores the extracted vbmeta image into vbmeta_images_ member object.
    vbmeta_images_.emplace(output_file_name, std::move(vbmeta_image));
}

// Generates a file with name |file_name| of size |image_size| with
// known content (0x00 0x01 0x02 .. 0xff 0x00 0x01 ..).
base::FilePath BaseFsAvbTest::GenerateImage(const std::string file_name, size_t image_size,
                                            uint8_t start_byte) {
    std::vector<uint8_t> image;
    image.resize(image_size);
    for (size_t n = 0; n < image_size; n++) {
        image[n] = uint8_t(n + start_byte);
    }
    base::FilePath image_path = test_dir_.Append(file_name);
    EXPECT_EQ(image_size,
              static_cast<const size_t>(base::WriteFile(
                      image_path, reinterpret_cast<const char*>(image.data()), image.size())));
    return image_path;
}

void BaseFsAvbTest::AddAvbFooter(const base::FilePath& image_path, const std::string& footer_type,
                                 const std::string& partition_name, const uint64_t partition_size,
                                 const std::string& avb_algorithm, uint64_t rollback_index,
                                 const base::FilePath& key_path, const std::string& salt,
                                 const std::string& additional_options) {
    // 'add_hash_footer' or 'add_hashtree_footer'.
    EXPECT_TRUE(footer_type == "hash" or footer_type == "hashtree");
    std::string add_footer_option = "add_" + footer_type + "_footer";

    std::string signing_options;
    if (avb_algorithm == "") {
        signing_options = " --algorithm NONE ";
    } else {
        signing_options =
                std::string(" --algorithm ") + avb_algorithm + " --key " + key_path.value() + " ";
    }
    EXPECT_COMMAND(0,
                   "avbtool %s"
                   " --image %s"
                   " --partition_name %s "
                   " --partition_size %" PRIu64 " --rollback_index %" PRIu64
                   " --salt %s"
                   " %s %s",
                   add_footer_option.c_str(), image_path.value().c_str(), partition_name.c_str(),
                   partition_size, rollback_index, salt.c_str(), signing_options.c_str(),
                   additional_options.c_str());
}

std::string BaseFsAvbTest::InfoImage(const base::FilePath& image_path) {
    base::FilePath tmp_path = test_dir_.Append("info_output.txt");
    EXPECT_COMMAND(0, "avbtool info_image --image %s --output %s", image_path.value().c_str(),
                   tmp_path.value().c_str());
    std::string info_data;
    EXPECT_TRUE(base::ReadFileToString(tmp_path, &info_data));
    return info_data;
}

std::string BaseFsAvbTest::InfoImage(const std::string& file_name) {
    auto iter = vbmeta_images_.find(file_name);
    EXPECT_NE(iter, vbmeta_images_.end());  // ensures file_name is generated before.
    // Gets the image path from iterator->second.path: VBMetaImage.path.
    base::FilePath image_path = iter->second.path;
    return InfoImage(image_path);
}

base::FilePath BaseFsAvbTest::ExtractPublicKeyAvb(const base::FilePath& key_path) {
    std::string file_name = key_path.RemoveExtension().BaseName().value();
    base::FilePath tmp_path = test_dir_.Append(file_name + "public_key.bin");
    EXPECT_COMMAND(0,
                   "avbtool extract_public_key --key %s"
                   " --output %s",
                   key_path.value().c_str(), tmp_path.value().c_str());
    return tmp_path;
}

std::string BaseFsAvbTest::ExtractPublicKeyAvbBlob(const base::FilePath& key_path) {
    base::FilePath tmp_path = test_dir_.Append("public_key.bin");
    EXPECT_COMMAND(0,
                   "avbtool extract_public_key --key %s"
                   " --output %s",
                   key_path.value().c_str(), tmp_path.value().c_str());
    std::string key_data;
    EXPECT_TRUE(base::ReadFileToString(tmp_path, &key_data));
    return key_data;
}

TEST_F(BaseFsAvbTest, GenerateImage) {
    const size_t image_size = 5 * 1024 * 1024;
    base::FilePath boot_path = GenerateImage("boot.img", image_size);
    EXPECT_NE(0U, boot_path.value().size());

    // Checks file size is as expected.
    int64_t file_size;
    ASSERT_TRUE(base::GetFileSize(boot_path, &file_size));
    EXPECT_EQ(file_size, image_size);

    // Checks file content is as expected.
    std::vector<uint8_t> expected_content;
    expected_content.resize(image_size);
    for (size_t n = 0; n < image_size; n++) {
        expected_content[n] = uint8_t(n);
    }
    std::vector<uint8_t> actual_content;
    actual_content.resize(image_size);
    EXPECT_TRUE(
            base::ReadFile(boot_path, reinterpret_cast<char*>(actual_content.data()), image_size));
    EXPECT_EQ(expected_content, actual_content);
}

TEST_F(BaseFsAvbTest, GenerateVBMetaImage) {
    GenerateVBMetaImage("vbmeta.img", "SHA256_RSA2048", 0,
                        base::FilePath("data/testkey_rsa2048.pem"),
                        {}, /* include_descriptor_image_paths */
                        {}, /* chain_partitions */
                        "--internal_release_string \"unit test\"");
    EXPECT_EQ("5eba9ad4e775645e7eac441a563c200681ae868158d06f6a6cd36d06c07bd781",
              CalcVBMetaDigest("vbmeta.img", "sha256"));
    EXPECT_EQ(
            "Minimum libavb version:   1.0\n"
            "Header Block:             256 bytes\n"
            "Authentication Block:     320 bytes\n"
            "Auxiliary Block:          576 bytes\n"
            "Algorithm:                SHA256_RSA2048\n"
            "Rollback Index:           0\n"
            "Flags:                    0\n"
            "Release String:           'unit test'\n"
            "Descriptors:\n"
            "    (none)\n",
            InfoImage("vbmeta.img"));
}

TEST_F(BaseFsAvbTest, AddHashFooter) {
    // Generates a raw boot.img
    const size_t image_size = 5 * 1024 * 1024;
    const size_t partition_size = 10 * 1024 * 1024;
    base::FilePath boot_path = GenerateImage("boot.img", image_size);
    EXPECT_NE(0U, boot_path.value().size());
    // Checks file size is as expected.
    int64_t file_size;
    ASSERT_TRUE(base::GetFileSize(boot_path, &file_size));
    EXPECT_EQ(file_size, image_size);
    // Appends AVB Hash Footer.
    AddAvbFooter(boot_path, "hash", "boot", partition_size, "SHA256_RSA4096", 10,
                 base::FilePath("data/testkey_rsa4096.pem"), "d00df00d",
                 "--internal_release_string \"unit test\"");
    // Extracts boot vbmeta from boot.img into boot-vbmeta.img.
    ExtractVBMetaImage(boot_path, "boot-vbmeta.img");
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
}

TEST_F(BaseFsAvbTest, AddHashtreeFooter) {
    // Generates a raw system.img
    const size_t image_size = 50 * 1024 * 1024;
    const size_t partition_size = 60 * 1024 * 1024;
    base::FilePath system_path = GenerateImage("system.img", image_size);
    EXPECT_NE(0U, system_path.value().size());
    // Checks file size is as expected.
    int64_t file_size;
    ASSERT_TRUE(base::GetFileSize(system_path, &file_size));
    EXPECT_EQ(file_size, image_size);
    // Appends AVB Hashtree Footer.
    AddAvbFooter(system_path, "hashtree", "system", partition_size, "SHA512_RSA8192", 20,
                 base::FilePath("data/testkey_rsa8192.pem"), "d00df00d",
                 "--internal_release_string \"unit test\"");
    // Extracts system vbmeta from system.img into system-vbmeta.img.
    ExtractVBMetaImage(system_path, "system-vbmeta.img");
    EXPECT_EQ(
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
            "      Image Size:            52428800 bytes\n"
            "      Tree Offset:           52428800\n"
            "      Tree Size:             413696 bytes\n"
            "      Data Block Size:       4096 bytes\n"
            "      Hash Block Size:       4096 bytes\n"
            "      FEC num roots:         2\n"
            "      FEC offset:            52842496\n"
            "      FEC size:              417792 bytes\n"
            "      Hash Algorithm:        sha1\n"
            "      Partition Name:        system\n"
            "      Salt:                  d00df00d\n"
            "      Root Digest:           d20d40c02298e385ab6d398a61a3b91dc9947d99\n"
            "      Flags:                 0\n",
            InfoImage("system-vbmeta.img"));
}

TEST_F(BaseFsAvbTest, GenerateVBMetaImageWithDescriptors) {
    // Generates a raw boot.img
    const size_t boot_image_size = 5 * 1024 * 1024;
    const size_t boot_partition_size = 10 * 1024 * 1024;
    base::FilePath boot_path = GenerateImage("boot.img", boot_image_size);
    // Adds AVB Hash Footer.
    AddAvbFooter(boot_path, "hash", "boot", boot_partition_size, "SHA256_RSA4096", 10,
                 base::FilePath("data/testkey_rsa4096.pem"), "d00df00d",
                 "--internal_release_string \"unit test\"");

    // Generates a raw system.img, use a smaller size to speed-up unit test.
    const size_t system_image_size = 10 * 1024 * 1024;
    const size_t system_partition_size = 15 * 1024 * 1024;
    base::FilePath system_path = GenerateImage("system.img", system_image_size);
    // Adds AVB Hashtree Footer.
    AddAvbFooter(system_path, "hashtree", "system", system_partition_size, "SHA512_RSA8192", 20,
                 base::FilePath("data/testkey_rsa8192.pem"), "d00df00d",
                 "--internal_release_string \"unit test\"");

    // Makes a vbmeta.img including both 'boot' and 'system' descriptors.
    GenerateVBMetaImage("vbmeta.img", "SHA256_RSA2048", 0,
                        base::FilePath("data/testkey_rsa2048.pem"),
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
}

TEST_F(BaseFsAvbTest, GenerateVBMetaImageWithChainDescriptors) {
    // Generates a raw boot.img
    const size_t boot_image_size = 5 * 1024 * 1024;
    const size_t boot_partition_size = 10 * 1024 * 1024;
    base::FilePath boot_path = GenerateImage("boot.img", boot_image_size);
    // Adds AVB Hash Footer.
    AddAvbFooter(boot_path, "hash", "boot", boot_partition_size, "SHA256_RSA2048", 10,
                 base::FilePath("data/testkey_rsa2048.pem"), "d00df00d",
                 "--internal_release_string \"unit test\"");

    // Generates a raw system.img, use a smaller size to speed-up unit test.
    const size_t system_image_size = 10 * 1024 * 1024;
    const size_t system_partition_size = 15 * 1024 * 1024;
    base::FilePath system_path = GenerateImage("system.img", system_image_size);
    // Adds AVB Hashtree Footer.
    AddAvbFooter(system_path, "hashtree", "system", system_partition_size, "SHA512_RSA4096", 20,
                 base::FilePath("data/testkey_rsa4096.pem"), "d00df00d",
                 "--internal_release_string \"unit test\"");

    // Make a vbmeta image with chain partitions.
    base::FilePath rsa2048_public_key =
            ExtractPublicKeyAvb(base::FilePath("data/testkey_rsa2048.pem"));
    base::FilePath rsa4096_public_key =
            ExtractPublicKeyAvb(base::FilePath("data/testkey_rsa4096.pem"));
    GenerateVBMetaImage("vbmeta.img", "SHA256_RSA8192", 0,
                        base::FilePath("data/testkey_rsa8192.pem"),
                        {},                               /* include_descriptor_image_paths */
                        {{"boot", 1, rsa2048_public_key}, /* chain_partitions */
                         {"system", 2, rsa4096_public_key}},
                        "--internal_release_string \"unit test\"");

    // vbmeta digest calculation includes the chained vbmeta from boot.img and system.img.
    EXPECT_EQ("abbe11b316901f3336e26630f64c4732dadbe14532186ac8640e4141a403721f",
              CalcVBMetaDigest("vbmeta.img", "sha256"));
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
}

}  // namespace fs_avb_host_test

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

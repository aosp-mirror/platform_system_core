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

#include "fs_avb_test_util.h"

#include <stdlib.h>

#include <android-base/file.h>
#include <base/files/file_util.h>
#include <base/strings/string_util.h>

namespace fs_avb_host_test {

// Need to match the data setting in Android.bp:
//     data: ["tests/data/*"]
base::FilePath BaseFsAvbTest::data_dir_ = base::FilePath("tests/data");

void BaseFsAvbTest::SetUp() {
    // Changes current directory to test executable directory so that relative path
    // references to test dependencies don't rely on being manually run from
    // the executable directory. With this, we can just open "./tests/data/testkey_rsa2048.pem"
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

base::FilePath BaseFsAvbTest::GenerateVBMetaImage(
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
    EXPECT_TRUE(base::GetFileSize(vbmeta_image.path, &file_size));
    vbmeta_image.content.resize(file_size);
    EXPECT_TRUE(base::ReadFile(vbmeta_image.path,
                               reinterpret_cast<char*>(vbmeta_image.content.data()), file_size));
    // Stores the generated vbmeta image into vbmeta_images_ member object.
    vbmeta_images_.emplace(file_name, std::move(vbmeta_image));

    return vbmeta_images_[file_name].path;  // returns the path.
}

base::FilePath BaseFsAvbTest::ExtractVBMetaImage(const base::FilePath& image_path,
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
    EXPECT_TRUE(base::GetFileSize(vbmeta_image.path, &file_size));
    vbmeta_image.content.resize(file_size);
    EXPECT_TRUE(base::ReadFile(vbmeta_image.path,
                               reinterpret_cast<char*>(vbmeta_image.content.data()), file_size));
    // Stores the extracted vbmeta image into vbmeta_images_ member object.
    vbmeta_images_.emplace(output_file_name, std::move(vbmeta_image));

    // Returns the output file path.
    return vbmeta_images_[output_file_name].path;
}

// Generates a file with name |file_name| of size |image_size| with
// known content (0x00 0x01 0x02 .. 0xff 0x00 0x01 ..).
base::FilePath BaseFsAvbTest::GenerateImage(const std::string& file_name, size_t image_size,
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

VBMetaData BaseFsAvbTest::GenerateImageAndExtractVBMetaData(
        const std::string& partition_name, const size_t image_size, const size_t partition_size,
        const std::string& footer_type, const base::FilePath& avb_signing_key,
        const std::string& avb_algorithm, const uint64_t rollback_index) {
    // Generates a raw image first
    base::FilePath image_path = GenerateImage(partition_name + ".img", image_size);

    // Appends AVB Hashtree Footer.
    AddAvbFooter(image_path, footer_type, partition_name, partition_size, avb_algorithm,
                 rollback_index, avb_signing_key, "d00df00d",
                 "--internal_release_string \"unit test\"");

    // Extracts vbmeta from the ram image into another *-vbmeta.img.
    auto vbmeta_image = ExtractVBMetaImage(image_path, partition_name + "-vbmeta.img");

    // Loads *-vbmeta.img into a VBMetaData.
    std::string vbmeta_buffer;
    EXPECT_TRUE(base::ReadFileToString(vbmeta_image, &vbmeta_buffer));

    return {(const uint8_t*)vbmeta_buffer.data(), vbmeta_buffer.size(), partition_name};
}

VBMetaData BaseFsAvbTest::LoadVBMetaData(const std::string& file_name) {
    auto iter = vbmeta_images_.find(file_name);
    EXPECT_NE(iter, vbmeta_images_.end());  // ensures file_name is generated before.

    // Gets the image path from iterator->second.path: VBMetaImage.path.
    base::FilePath image_path = iter->second.path;

    // Loads the vbmeta_image into a VBMetaData.
    std::string vbmeta_buffer;
    EXPECT_TRUE(base::ReadFileToString(image_path, &vbmeta_buffer));

    std::string partition_name = image_path.RemoveExtension().BaseName().value();
    return {(const uint8_t*)vbmeta_buffer.data(), vbmeta_buffer.size(), partition_name};
}

VBMetaData BaseFsAvbTest::ExtractAndLoadVBMetaData(const base::FilePath& image_path,
                                                   const std::string& output_file_name) {
    ExtractVBMetaImage(image_path, output_file_name);
    return LoadVBMetaData(output_file_name);
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

}  // namespace fs_avb_host_test

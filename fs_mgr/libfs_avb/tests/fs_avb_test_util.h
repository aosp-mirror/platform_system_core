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

#pragma once

#include <inttypes.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/strings/stringprintf.h>
#include <gtest/gtest.h>

// Utility macro to run the command expressed by the printf()-style string
// |command_format| using the system(3) utility function. Will assert unless
// the command exits normally with exit status |expected_exit_status|.
#define EXPECT_COMMAND(expected_exit_status, command_format, ...)                   \
    do {                                                                            \
        int rc = system(base::StringPrintf(command_format, ##__VA_ARGS__).c_str()); \
        EXPECT_TRUE(WIFEXITED(rc));                                                 \
        EXPECT_EQ(WEXITSTATUS(rc), expected_exit_status);                           \
    } while (0);

namespace fs_avb_host_test {

struct VBMetaImage {
    // Path to vbmeta image generated with GenerateVBMetaImage().
    base::FilePath path;
    // Contents of the image generated with GenerateVBMetaImage().
    std::vector<uint8_t> content;
};

struct ChainPartitionConfig {
    std::string partition_name;
    uint32_t rollback_index_location;
    base::FilePath key_blob_path;
};

/* Base-class used for unit test. */
class BaseFsAvbTest : public ::testing::Test {
  public:
    BaseFsAvbTest() {}

  protected:
    virtual ~BaseFsAvbTest() {}

    // Calculates the vbmeta digest using 'avbtool calc_vbmeta_digest' command.
    // Note that the calculation includes chained vbmeta images.
    std::string CalcVBMetaDigest(const std::string& file_name, const std::string& hash_algorithm);

    // Generates a vbmeta image with |file_name| by avbtool.
    // The generated vbmeta image will be written to disk, see the
    // |vbmeta_images_| variable for its path and the content.
    void GenerateVBMetaImage(const std::string& file_name, const std::string& avb_algorithm,
                             uint64_t rollback_index, const base::FilePath& key_path,
                             const std::vector<base::FilePath>& include_descriptor_image_paths,
                             const std::vector<ChainPartitionConfig>& chain_partitions,
                             const std::string& additional_options = "");
    // Similar to above, but extracts a vbmeta image from the given image_path.
    // The extracted vbmeta image will be written to disk, with |output_file_name|.
    // See the |vbmeta_images_| variable for its path and the content.
    void ExtractVBMetaImage(const base::FilePath& image_path, const std::string& output_file_name,
                            const size_t padding_size = 0);

    // Generate a file with name |file_name| of size |image_size| with
    // known content (0x00 0x01 0x02 .. 0xff 0x00 0x01 ..).
    base::FilePath GenerateImage(const std::string& file_name, size_t image_size,
                                 uint8_t start_byte = 0);
    // Invokes 'avbtool add_hash_footer' or 'avbtool add_hashtree_footer' to sign
    // the |image_path|. The |footer_type| can be either "hash" or "hashtree".
    void AddAvbFooter(const base::FilePath& image_path, const std::string& footer_type,
                      const std::string& partition_name, const uint64_t partition_size,
                      const std::string& avb_algorithm, uint64_t rollback_index,
                      const base::FilePath& key_path, const std::string& salt = "d00df00d",
                      const std::string& additional_options = "");

    // Returns the output of 'avbtool info_image' for the |image_path|.
    std::string InfoImage(const base::FilePath& image_path);
    // Same as above, but for an internal vbmeta image with |file_name| in |vbmeta_images_|.
    std::string InfoImage(const std::string& file_name);

    // Extracts public key blob in AVB format for a .pem key, then returns the
    // file path: a .bin file.
    base::FilePath ExtractPublicKeyAvb(const base::FilePath& key_path);
    // Same as above, but returns the key blob binary instead.
    std::string ExtractPublicKeyAvbBlob(const base::FilePath& key_path);

    void SetUp() override;
    void TearDown() override;

    // Temporary directory created in SetUp().
    base::FilePath test_dir_;
    // Maps vbmeta image name (e.g., vbmeta_a.img, system_a.img) to VBMetaImage.
    std::map<std::string, VBMetaImage> vbmeta_images_;

    static base::FilePath data_dir_;
};

}  // namespace fs_avb_host_test

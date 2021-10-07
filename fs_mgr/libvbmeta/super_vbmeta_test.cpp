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

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <android-base/file.h>
#include <gtest/gtest.h>
#include <openssl/sha.h>
#include <sparse/sparse.h>

#include "reader.h"
#include "super_vbmeta_format.h"
#include "utility.h"
#include "writer.h"

#define FAKE_DATA_SIZE 40960
#define FAKE_PARTITION_SIZE FAKE_DATA_SIZE * 25

using android::base::Result;
using android::fs_mgr::GetFileSize;
using android::fs_mgr::ReadVBMetaImage;
using SparsePtr = std::unique_ptr<sparse_file, decltype(&sparse_file_destroy)>;

void GeneratePartitionImage(int fd, const std::string& file_name,
                            const std::string& partition_name) {
    std::unique_ptr<uint8_t[]> buffer = std::make_unique<uint8_t[]>(FAKE_DATA_SIZE);
    for (size_t c = 0; c < FAKE_DATA_SIZE; c++) {
        buffer[c] = uint8_t(c);
    }

    SparsePtr file(sparse_file_new(512 /* block size */, FAKE_DATA_SIZE), sparse_file_destroy);
    EXPECT_TRUE(file);
    EXPECT_EQ(0, sparse_file_add_data(file.get(), buffer.get(), FAKE_DATA_SIZE,
                                      0 /* offset in blocks */));
    EXPECT_EQ(0, sparse_file_write(file.get(), fd, false /* gz */, true /* sparse */,
                                   false /* crc */));

    std::stringstream cmd;
    cmd << "avbtool add_hashtree_footer"
        << " --image " << file_name << " --partition_name " << partition_name
        << " --partition_size " << FAKE_PARTITION_SIZE << " --algorithm SHA256_RSA2048"
        << " --key data/testkey_rsa2048.pem";

    int rc = system(cmd.str().c_str());
    EXPECT_TRUE(WIFEXITED(rc));
    EXPECT_EQ(WEXITSTATUS(rc), 0);
}

void GenerateVBMetaImage(const std::string& vbmeta_file_name,
                         const std::string& include_file_name) {
    std::stringstream cmd;
    cmd << "avbtool make_vbmeta_image"
        << " --output " << vbmeta_file_name << " --include_descriptors_from_image "
        << include_file_name;

    int rc = system(cmd.str().c_str());
    EXPECT_TRUE(WIFEXITED(rc));
    EXPECT_EQ(WEXITSTATUS(rc), 0);
}

std::string ReadVBMetaImageFromFile(const std::string& file) {
    android::base::unique_fd fd(open(file.c_str(), O_RDONLY | O_CLOEXEC));
    EXPECT_GT(fd, 0);
    Result<uint64_t> file_size = GetFileSize(fd);
    EXPECT_RESULT_OK(file_size);
    std::unique_ptr<uint8_t[]> buffer = std::make_unique<uint8_t[]>(VBMETA_IMAGE_MAX_SIZE);
    EXPECT_TRUE(android::base::ReadFully(fd, buffer.get(), file_size.value()));
    return std::string(reinterpret_cast<char*>(buffer.get()), VBMETA_IMAGE_MAX_SIZE);
}

TEST(VBMetaTableTest, VBMetaTableBasic) {
    TemporaryDir td;

    // Generate Partition Image
    TemporaryFile system_tf(std::string(td.path));
    std::string system_path(system_tf.path);
    GeneratePartitionImage(system_tf.fd, system_path, "system");
    system_tf.release();

    TemporaryFile vendor_tf(std::string(td.path));
    std::string vendor_path(vendor_tf.path);
    GeneratePartitionImage(vendor_tf.fd, vendor_path, "vendor");
    vendor_tf.release();

    TemporaryFile product_tf(std::string(td.path));
    std::string product_path(product_tf.path);
    GeneratePartitionImage(product_tf.fd, product_path, "product");
    product_tf.release();

    // Generate VBMeta Image
    std::string vbmeta_system_path(td.path);
    vbmeta_system_path.append("/vbmeta_system.img");
    GenerateVBMetaImage(vbmeta_system_path, system_path);

    std::string vbmeta_vendor_path(td.path);
    vbmeta_vendor_path.append("/vbmeta_vendor.img");
    GenerateVBMetaImage(vbmeta_vendor_path, vendor_path);

    std::string vbmeta_product_path(td.path);
    vbmeta_product_path.append("/vbmeta_product.img");
    GenerateVBMetaImage(vbmeta_product_path, product_path);

    // Generate Super VBMeta Image
    std::string super_vbmeta_path(td.path);
    super_vbmeta_path.append("/super_vbmeta.img");

    std::stringstream cmd;
    cmd << "vbmake"
        << " --image "
        << "vbmeta_system"
        << "=" << vbmeta_system_path << " --image "
        << "vbmeta_vendor"
        << "=" << vbmeta_vendor_path << " --image "
        << "vbmeta_product"
        << "=" << vbmeta_product_path << " --output=" << super_vbmeta_path;

    int rc = system(cmd.str().c_str());
    ASSERT_TRUE(WIFEXITED(rc));
    ASSERT_EQ(WEXITSTATUS(rc), 0);

    android::base::unique_fd fd(open(super_vbmeta_path.c_str(), O_RDONLY | O_CLOEXEC));
    EXPECT_GT(fd, 0);

    // Check the size of vbmeta table
    Result<uint64_t> super_vbmeta_size = GetFileSize(fd);
    EXPECT_RESULT_OK(super_vbmeta_size);
    EXPECT_EQ(super_vbmeta_size.value(),
              SUPER_VBMETA_TABLE_MAX_SIZE * 2 + VBMETA_IMAGE_MAX_SIZE * 3);

    // Check Primary vbmeta table is equal to Backup one
    VBMetaTable table;
    EXPECT_RESULT_OK(android::fs_mgr::ReadPrimaryVBMetaTable(fd, &table));
    VBMetaTable table_backup;
    EXPECT_RESULT_OK(android::fs_mgr::ReadBackupVBMetaTable(fd, &table_backup));
    EXPECT_EQ(android::fs_mgr::SerializeVBMetaTable(table),
              android::fs_mgr::SerializeVBMetaTable(table_backup));

    // Check vbmeta table Header Checksum
    std::string serial_table = android::fs_mgr::SerializeVBMetaTable(table);
    std::string serial_removed_checksum(serial_table);
    // Replace checksum 32 bytes (starts at 16th byte) with 0
    serial_removed_checksum.replace(16, 32, 32, 0);
    uint8_t test_checksum[32];
    ::SHA256(reinterpret_cast<const uint8_t*>(serial_removed_checksum.c_str()),
             table.header.total_size, &test_checksum[0]);
    EXPECT_EQ(memcmp(table.header.checksum, test_checksum, 32), 0);

    // Check vbmeta table descriptors and vbmeta images
    EXPECT_EQ(table.descriptors.size(), 3);

    EXPECT_EQ(table.descriptors[0].vbmeta_index, 0);
    EXPECT_EQ(table.descriptors[0].vbmeta_name_length, 14);
    EXPECT_EQ(table.descriptors[0].vbmeta_name, "vbmeta_product");
    Result<std::string> vbmeta_product_content = ReadVBMetaImage(fd, 0);
    EXPECT_RESULT_OK(vbmeta_product_content);
    EXPECT_EQ(ReadVBMetaImageFromFile(vbmeta_product_path), vbmeta_product_content.value());

    EXPECT_EQ(table.descriptors[1].vbmeta_index, 1);
    EXPECT_EQ(table.descriptors[1].vbmeta_name_length, 13);
    EXPECT_EQ(table.descriptors[1].vbmeta_name, "vbmeta_system");
    Result<std::string> vbmeta_system_content = ReadVBMetaImage(fd, 1);
    EXPECT_RESULT_OK(vbmeta_system_content);
    EXPECT_EQ(ReadVBMetaImageFromFile(vbmeta_system_path), vbmeta_system_content.value());

    EXPECT_EQ(table.descriptors[2].vbmeta_index, 2);
    EXPECT_EQ(table.descriptors[2].vbmeta_name_length, 13);
    EXPECT_EQ(table.descriptors[2].vbmeta_name, "vbmeta_vendor");
    Result<std::string> vbmeta_vendor_content = ReadVBMetaImage(fd, 2);
    EXPECT_RESULT_OK(vbmeta_vendor_content);
    EXPECT_EQ(ReadVBMetaImageFromFile(vbmeta_vendor_path), vbmeta_vendor_content.value());
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

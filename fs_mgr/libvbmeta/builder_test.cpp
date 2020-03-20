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

#include <gtest/gtest.h>

#include "builder.h"
#include "super_vbmeta_format.h"

using android::base::Result;
using android::fs_mgr::SuperVBMetaBuilder;

TEST(BuilderTest, VBMetaTableBasic) {
    std::unique_ptr<SuperVBMetaBuilder> builder = std::make_unique<SuperVBMetaBuilder>();
    ASSERT_NE(builder, nullptr);

    Result<uint8_t> vbmeta_index = builder->AddVBMetaImage("vbmeta" /* vbmeta_name */);
    EXPECT_RESULT_OK(vbmeta_index);

    Result<uint8_t> vbmeta_system_slot = builder->AddVBMetaImage("vbmeta_system" /* vbmeta_name */);
    EXPECT_RESULT_OK(vbmeta_system_slot);

    Result<uint8_t> vbmeta_vendor_slot = builder->AddVBMetaImage("vbmeta_vendor" /* vbmeta_name */);
    EXPECT_RESULT_OK(vbmeta_vendor_slot);

    builder->DeleteVBMetaImage("vbmeta_system" /* vbmeta_name */);

    Result<uint8_t> vbmeta_product_slot =
            builder->AddVBMetaImage("vbmeta_product" /* vbmeta_name */);
    EXPECT_RESULT_OK(vbmeta_product_slot);

    std::unique_ptr<VBMetaTable> table = builder->ExportVBMetaTable();
    ASSERT_NE(table, nullptr);

    // check for vbmeta table header
    EXPECT_EQ(table->header.magic, SUPER_VBMETA_MAGIC);
    EXPECT_EQ(table->header.major_version, SUPER_VBMETA_MAJOR_VERSION);
    EXPECT_EQ(table->header.minor_version, SUPER_VBMETA_MINOR_VERSION);
    EXPECT_EQ(table->header.header_size, SUPER_VBMETA_HEADER_SIZE);
    EXPECT_EQ(table->header.total_size,
              SUPER_VBMETA_HEADER_SIZE + SUPER_VBMETA_DESCRIPTOR_SIZE * 3 + 33);
    EXPECT_EQ(table->header.descriptors_size, SUPER_VBMETA_DESCRIPTOR_SIZE * 3 + 33);

    // Test for vbmeta table descriptors
    EXPECT_EQ(table->descriptors.size(), 3);

    EXPECT_EQ(table->descriptors[0].vbmeta_index, 0);
    EXPECT_EQ(table->descriptors[0].vbmeta_name_length, 6);
    for (int i = 0; i < sizeof(table->descriptors[0].reserved); i++)
        EXPECT_EQ(table->descriptors[0].reserved[i], 0);
    EXPECT_EQ(table->descriptors[0].vbmeta_name, "vbmeta");

    EXPECT_EQ(table->descriptors[1].vbmeta_index, 2);
    EXPECT_EQ(table->descriptors[1].vbmeta_name_length, 13);
    for (int i = 0; i < sizeof(table->descriptors[1].reserved); i++)
        EXPECT_EQ(table->descriptors[1].reserved[i], 0);
    EXPECT_EQ(table->descriptors[1].vbmeta_name, "vbmeta_vendor");

    EXPECT_EQ(table->descriptors[2].vbmeta_index, 1);
    EXPECT_EQ(table->descriptors[2].vbmeta_name_length, 14);
    for (int i = 0; i < sizeof(table->descriptors[2].reserved); i++)
        EXPECT_EQ(table->descriptors[2].reserved[i], 0);
    EXPECT_EQ(table->descriptors[2].vbmeta_name, "vbmeta_product");
}

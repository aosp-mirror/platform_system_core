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

#include <android-base/properties.h>
#include <fs_avb/fs_avb_util.h>
#include <fstab/fstab.h>
#include <gtest/gtest.h>

#include <sys/types.h>
#include <unistd.h>

using android::fs_mgr::Fstab;
using android::fs_mgr::FstabEntry;
using android::fs_mgr::VBMetaData;
using android::fs_mgr::VBMetaVerifyResult;

namespace fs_avb_device_test {

// system vbmeta might not be at the end of /system when dynamic partition is
// enabled. Therefore, disable it by default.
TEST(PublicFsAvbDeviceTest, DISABLED_LoadAndVerifyVbmeta_SystemVbmeta) {
    Fstab fstab;
    EXPECT_TRUE(ReadDefaultFstab(&fstab));

    FstabEntry* system_entry = GetEntryForMountPoint(&fstab, "/system");
    EXPECT_NE(nullptr, system_entry);

    std::string out_public_key_data;
    std::string out_avb_partition_name;
    VBMetaVerifyResult out_verify_result;
    std::unique_ptr<VBMetaData> vbmeta =
            LoadAndVerifyVbmeta(*system_entry, "" /* expected_public_key_blob */,
                                &out_public_key_data, &out_avb_partition_name, &out_verify_result);

    EXPECT_NE(nullptr, vbmeta);
    EXPECT_EQ(VBMetaVerifyResult::kSuccess, out_verify_result);
    EXPECT_EQ("system", out_avb_partition_name);
    EXPECT_NE("", out_public_key_data);
}

TEST(PublicFsAvbDeviceTest, GetHashtreeDescriptor_SystemOther) {
    // Non-A/B device doesn't have system_other partition.
    if (fs_mgr_get_slot_suffix() == "") return;

    // Skip running this test if system_other is a logical partition.
    // Note that system_other is still a physical partition on "retrofit" devices.
    if (android::base::GetBoolProperty("ro.boot.dynamic_partitions", false) &&
        !android::base::GetBoolProperty("ro.boot.dynamic_partitions_retrofit", false)) {
        return;
    }

    Fstab fstab;
    EXPECT_TRUE(ReadFstabFromFile("/system/etc/fstab.postinstall", &fstab));

    // It should have two lines in the fstab, the first for logical system_other,
    // the other for physical system_other.
    EXPECT_EQ(2UL, fstab.size());

    // Use the 2nd fstab entry, which is for physical system_other partition.
    FstabEntry* system_other = &fstab[1];
    EXPECT_NE(nullptr, system_other);

    std::string out_public_key_data;
    std::string out_avb_partition_name;
    VBMetaVerifyResult out_verify_result;
    std::unique_ptr<VBMetaData> system_other_vbmeta =
            LoadAndVerifyVbmeta(*system_other, "" /* expected_public_key_blob */,
                                &out_public_key_data, &out_avb_partition_name, &out_verify_result);

    EXPECT_NE(nullptr, system_other_vbmeta);
    EXPECT_EQ(VBMetaVerifyResult::kSuccess, out_verify_result);
    EXPECT_EQ("system_other", out_avb_partition_name);
    EXPECT_NE("", out_public_key_data);

    auto hashtree_desc =
            GetHashtreeDescriptor(out_avb_partition_name, std::move(*system_other_vbmeta));
    EXPECT_NE(nullptr, hashtree_desc);
}

}  // namespace fs_avb_device_test

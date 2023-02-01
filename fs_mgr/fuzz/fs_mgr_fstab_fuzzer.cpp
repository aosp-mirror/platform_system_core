//
// Copyright (C) 2021 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#include <string>
#include <vector>

#include <fstab/fstab.h>
#include <fuzzer/FuzzedDataProvider.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    std::string make_fstab_str = fdp.ConsumeRandomLengthString();
    std::string dsu_slot = fdp.ConsumeRandomLengthString(30);
    std::vector<std::string> dsu_partitions = {
            fdp.ConsumeRandomLengthString(30),
            fdp.ConsumeRandomLengthString(30),
    };
    std::string skip_mount_config = fdp.ConsumeRemainingBytesAsString();

    android::fs_mgr::Fstab fstab;
    android::fs_mgr::ParseFstabFromString(make_fstab_str, /* proc_mounts = */ false, &fstab);
    android::fs_mgr::TransformFstabForDsu(&fstab, dsu_slot, dsu_partitions);
    android::fs_mgr::SkipMountWithConfig(skip_mount_config, &fstab, /* verbose = */ false);

    return 0;
}

// Copyright (C) 2023 The Android Open Source Project
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

#include <fcntl.h>
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include <iostream>
#include <memory>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/unique_fd.h>
#include <gflags/gflags.h>
#include "user-space-merge/extractor.h"

using namespace std::string_literals;

DEFINE_string(base, "", "Base device/image");
DEFINE_string(cow, "", "COW device/image");
DEFINE_string(out, "", "Output path");
DEFINE_int32(num_sectors, 0, "Number of sectors to read");

int main([[maybe_unused]] int argc, [[maybe_unused]] char** argv) {
    android::base::InitLogging(argv);
    gflags::ParseCommandLineFlags(&argc, &argv, true);

    if (FLAGS_out.empty()) {
        LOG(ERROR) << "Missing -out argument.";
        return 1;
    }
    if (FLAGS_base.empty()) {
        LOG(ERROR) << "Missing -base argument.";
        return 1;
    }
    if (FLAGS_cow.empty()) {
        LOG(ERROR) << "missing -out argument.";
        return 1;
    }
    if (!FLAGS_num_sectors) {
        LOG(ERROR) << "missing -num_sectors argument.";
        return 1;
    }

    android::snapshot::Extractor extractor(FLAGS_base, FLAGS_cow);
    if (!extractor.Init()) {
        return 1;
    }
    if (!extractor.Extract(FLAGS_num_sectors, FLAGS_out)) {
        return 1;
    }
    return 0;
}

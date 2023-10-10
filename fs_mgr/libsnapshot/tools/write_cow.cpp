//
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
//
#include <android-base/file.h>
#include <android-base/logging.h>
#include <libsnapshot/cow_compress.h>
#include <libsnapshot/cow_format.h>
#include <libsnapshot/cow_writer.h>

#include <gflags/gflags.h>
#include <iostream>

#include "android-base/unique_fd.h"

DEFINE_bool(silent, false, "Run silently");
DEFINE_int32(writer_version, 2, "which version of COW writer to be used");
DEFINE_bool(write_legacy, false,
            "Writes a legacy cow_v2 in current directory, this cow was used to test backwards "
            "compatibility between version 2 and version 3");
DEFINE_bool(write_header, false, "Test reading/writing just the header");
using namespace android::snapshot;

// This writes a simple cow v2 file in the current directory. This file will serve as testdata for
// ensuring our v3 cow reader will be able to read a cow file created by the v2 writer.
//
// WARNING: We should not be overriding this test file, as it will serve as historic marker for what
// a device with old writer_v2 will write as a cow.
static void write_legacy_cow_v2() {
    CowOptions options;
    options.cluster_ops = 5;
    options.num_merge_ops = 1;
    std::string data = "This is some data, believe it";
    data.resize(options.block_size, '\0');

    char cwd_buffer[1024];
    size_t cwd_buffer_size = sizeof(cwd_buffer);

    // Get the current working directory path.
    char* err = getcwd(cwd_buffer, cwd_buffer_size);
    if (!err) {
        LOG(ERROR) << "Couldn't get current directory";
    }
    android::base::unique_fd fd(open(strcat(cwd_buffer, "/cow_v2"), O_CREAT | O_RDWR, 0666));
    if (fd.get() == -1) {
        LOG(FATAL) << "couldn't open tmp_cow";
    }
    std::unique_ptr<ICowWriter> writer = CreateCowWriter(2, options, std::move(fd));
    writer->AddCopy(0, 5);
    writer->AddRawBlocks(2, data.data(), data.size());
    writer->AddLabel(1);
    writer->AddXorBlocks(50, data.data(), data.size(), 24, 10);
    writer->AddZeroBlocks(5, 10);
    writer->AddLabel(2);
    writer->Finalize();
}

static bool WriteCow(const std::string& path) {
    android::base::unique_fd fd(open(path.c_str(), O_RDONLY));
    fd.reset(open(path.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0664));
    if (fd < 0) {
        PLOG(ERROR) << "could not open " << path << " for writing";
        return false;
    }
    CowOptions options;
    std::string data = "This is some data, believe it";
    data.resize(options.block_size, '\0');

    std::unique_ptr<ICowWriter> writer =
            CreateCowWriter(FLAGS_writer_version, options, std::move(fd));
    if (!writer) {
        return false;
    }

    writer->AddCopy(0, 5);
    writer->AddRawBlocks(2, data.data(), data.size());
    writer->AddLabel(1);
    writer->AddXorBlocks(50, data.data(), data.size(), 24, 10);
    writer->AddZeroBlocks(5, 10);
    writer->AddLabel(2);
    writer->Finalize();

    if (!FLAGS_silent) {
        std::cout << "Writing COW with writer v" << FLAGS_writer_version << "\n";
    }

    return true;
}

int main(int argc, char** argv) {
    gflags::ParseCommandLineFlags(&argc, &argv, true);
    if (FLAGS_write_legacy) {
        write_legacy_cow_v2();
        return 0;
    }
    if (argc < 2) {
        gflags::ShowUsageWithFlags(argv[0]);
        return 1;
    }
    if (!WriteCow(argv[1])) {
        return 1;
    }
}

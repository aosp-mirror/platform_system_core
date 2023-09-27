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
#include <filesystem>

#include "android-base/unique_fd.h"

using namespace android::snapshot;

// This writes a simple cow v2 file in the current directory. This file will serve as testdata for
// ensuring our v3 cow reader will be able to read a cow file created by the v2 writer.
//
// WARNING: We should not be overriding this test file, as it will serve as historic marker for what
// a device with old writer_v2 will write as a cow.
void write_cow_v2() {
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

int main() {
    write_cow_v2();
}

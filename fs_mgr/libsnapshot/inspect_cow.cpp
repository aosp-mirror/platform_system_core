//
// Copyright (C) 2020 The Android Open Source Project
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
#include <stdio.h>

#include <iostream>
#include <string>

#include <android-base/logging.h>
#include <android-base/unique_fd.h>
#include <libsnapshot/cow_reader.h>

namespace android {
namespace snapshot {

void MyLogger(android::base::LogId, android::base::LogSeverity severity, const char*, const char*,
              unsigned int, const char* message) {
    if (severity == android::base::ERROR) {
        fprintf(stderr, "%s\n", message);
    } else {
        fprintf(stdout, "%s\n", message);
    }
}

static bool Inspect(const std::string& path) {
    android::base::unique_fd fd(open(path.c_str(), O_RDONLY));
    if (fd < 0) {
        PLOG(ERROR) << "open failed: " << path;
        return false;
    }

    CowReader reader;
    if (!reader.Parse(fd)) {
        LOG(ERROR) << "parse failed: " << path;
        return false;
    }

    CowHeader header;
    if (!reader.GetHeader(&header)) {
        LOG(ERROR) << "could not get header: " << path;
        return false;
    }

    std::cout << "Major version: " << header.major_version << "\n";
    std::cout << "Minor version: " << header.minor_version << "\n";
    std::cout << "Header size: " << header.header_size << "\n";
    std::cout << "Footer size: " << header.footer_size << "\n";
    std::cout << "Block size: " << header.block_size << "\n";
    std::cout << "\n";

    auto iter = reader.GetOpIter();
    while (!iter->Done()) {
        const CowOperation& op = iter->Get();

        std::cout << op << "\n";

        iter->Next();
    }

    return true;
}

}  // namespace snapshot
}  // namespace android

int main(int argc, char** argv) {
    android::base::InitLogging(argv, android::snapshot::MyLogger);

    if (argc < 2) {
        LOG(ERROR) << "Usage: inspect_cow <COW_FILE>";
        return 1;
    }

    if (!android::snapshot::Inspect(argv[1])) {
        return 1;
    }
    return 0;
}

//
// Copyright (C) 2019 The Android Open Source Project
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

#include <sysexits.h>

#include <chrono>
#include <iostream>
#include <map>
#include <sstream>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/unique_fd.h>

#include <libsnapshot/snapshot.h>

using namespace std::string_literals;

int Usage() {
    std::cerr << "snapshotctl: Control snapshots.\n"
                 "Usage: snapshotctl [action] [flags]\n"
                 "Actions:\n"
                 "  dump\n"
                 "    Print snapshot states.\n"
                 "  merge\n"
                 "    Deprecated.\n";
    return EX_USAGE;
}

namespace android {
namespace snapshot {

bool DumpCmdHandler(int /*argc*/, char** argv) {
    android::base::InitLogging(argv, &android::base::StderrLogger);
    return SnapshotManager::New()->Dump(std::cout);
}

bool MergeCmdHandler(int /*argc*/, char** argv) {
    android::base::InitLogging(argv, &android::base::StderrLogger);
    LOG(WARNING) << "Deprecated. Call update_engine_client --merge instead.";
    return false;
}

static std::map<std::string, std::function<bool(int, char**)>> kCmdMap = {
        // clang-format off
        {"dump", DumpCmdHandler},
        {"merge", MergeCmdHandler},
        // clang-format on
};

}  // namespace snapshot
}  // namespace android

int main(int argc, char** argv) {
    using namespace android::snapshot;
    if (argc < 2) {
        return Usage();
    }

    for (const auto& cmd : kCmdMap) {
        if (cmd.first == argv[1]) {
            return cmd.second(argc, argv) ? EX_OK : EX_SOFTWARE;
        }
    }

    return Usage();
}

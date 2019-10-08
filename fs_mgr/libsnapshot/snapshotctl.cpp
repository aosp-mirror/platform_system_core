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

#include <android-base/logging.h>
#include <libsnapshot/snapshot.h>

using namespace std::string_literals;

int Usage() {
    std::cerr << "snapshotctl: Control snapshots.\n"
                 "Usage: snapshotctl [action] [flags]\n"
                 "Actions:\n"
                 "  dump\n"
                 "    Print snapshot states.\n"
                 "  merge [--logcat]\n"
                 "    Initialize merge and wait for it to be completed.\n"
                 "    If --logcat is specified, log to logcat. Otherwise, log to stdout.\n";
    return EX_USAGE;
}

namespace android {
namespace snapshot {

bool DumpCmdHandler(int /*argc*/, char** argv) {
    android::base::InitLogging(argv, &android::base::StderrLogger);
    return SnapshotManager::New()->Dump(std::cout);
}

bool MergeCmdHandler(int argc, char** argv) {
    auto begin = std::chrono::steady_clock::now();

    bool log_to_logcat = false;
    for (int i = 2; i < argc; ++i) {
        if (argv[i] == "--logcat"s) {
            log_to_logcat = true;
        }
    }
    if (log_to_logcat) {
        android::base::InitLogging(argv);
    } else {
        android::base::InitLogging(argv, &android::base::StdioLogger);
    }

    auto sm = SnapshotManager::New();

    auto state = sm->GetUpdateState();
    if (state == UpdateState::None) {
        LOG(INFO) << "Can't find any snapshot to merge.";
        return true;
    }
    if (state == UpdateState::Unverified) {
        if (!sm->InitiateMerge()) {
            LOG(ERROR) << "Failed to initiate merge.";
            return false;
        }
    }

    // All other states can be handled by ProcessUpdateState.
    LOG(INFO) << "Waiting for any merge to complete. This can take up to 1 minute.";
    state = SnapshotManager::New()->ProcessUpdateState();

    if (state == UpdateState::MergeCompleted) {
        auto end = std::chrono::steady_clock::now();
        auto passed = std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count();
        LOG(INFO) << "Snapshot merged in " << passed << " ms.";
        return true;
    }

    LOG(ERROR) << "Snapshot failed to merge with state \"" << state << "\".";
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

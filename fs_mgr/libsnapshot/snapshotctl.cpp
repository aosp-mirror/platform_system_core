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
#include "utility.h"

#include "utility.h"

using namespace std::string_literals;

int Usage() {
    std::cerr << "snapshotctl: Control snapshots.\n"
                 "Usage: snapshotctl [action] [flags]\n"
                 "Actions:\n"
                 "  dump\n"
                 "    Print snapshot states.\n"
                 "  merge [--logcat] [--log-to-file]\n"
                 "    Initialize merge and wait for it to be completed.\n"
                 "    If --logcat is specified, log to logcat.\n"
                 "    If --log-to-file is specified, log to /data/misc/snapshotctl_log/.\n"
                 "    If both specified, log to both. If none specified, log to stdout.\n";
    return EX_USAGE;
}

namespace android {
namespace snapshot {

bool DumpCmdHandler(int /*argc*/, char** argv) {
    android::base::InitLogging(argv, &android::base::StderrLogger);
    return SnapshotManager::New()->Dump(std::cout);
}

class FileLogger {
  public:
    FileLogger() {
        static constexpr const char* kLogFilePath = "/data/misc/snapshotctl_log/";
        std::stringstream ss;
        ss << kLogFilePath << "snapshotctl." << Now() << ".log";
        fd_.reset(TEMP_FAILURE_RETRY(
                open(ss.str().c_str(),
                     O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW | O_SYNC, 0660)));
    }
    // Copy-contuctor needed to be converted to std::function.
    FileLogger(const FileLogger& other) { fd_.reset(dup(other.fd_)); }
    void operator()(android::base::LogId, android::base::LogSeverity, const char* /*tag*/,
                    const char* /*file*/, unsigned int /*line*/, const char* message) {
        if (fd_ == -1) return;
        std::stringstream ss;
        ss << Now() << ":" << message << "\n";
        (void)android::base::WriteStringToFd(ss.str(), fd_);
    }

  private:
    android::base::unique_fd fd_;
};

class MergeCmdLogger {
  public:
    MergeCmdLogger(int argc, char** argv) {
        for (int i = 0; i < argc; ++i) {
            if (argv[i] == "--logcat"s) {
                loggers_.push_back(android::base::LogdLogger());
            }
            if (argv[i] == "--log-to-file"s) {
                loggers_.push_back(std::move(FileLogger()));
            }
        }
        if (loggers_.empty()) {
            loggers_.push_back(&android::base::StdioLogger);
        }
    }
    void operator()(android::base::LogId id, android::base::LogSeverity severity, const char* tag,
                    const char* file, unsigned int line, const char* message) {
        for (auto&& logger : loggers_) {
            logger(id, severity, tag, file, line, message);
        }
    }

  private:
    std::vector<android::base::LogFunction> loggers_;
};

bool MergeCmdHandler(int argc, char** argv) {
    auto begin = std::chrono::steady_clock::now();

    // 'snapshotctl merge' is stripped away from arguments to
    // Logger.
    android::base::InitLogging(argv, MergeCmdLogger(argc - 2, argv + 2));

    auto state = SnapshotManager::New()->InitiateMergeAndWait();

    if (state == UpdateState::None) {
        return true;
    }
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

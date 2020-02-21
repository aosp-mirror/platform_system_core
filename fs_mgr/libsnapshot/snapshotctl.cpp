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
#include <android/snapshot/snapshot.pb.h>
#include <libsnapshot/snapshot.h>
#include <statslog.h>

#include "snapshot_stats.h"
#include "utility.h"

using namespace std::string_literals;

int Usage() {
    std::cerr << "snapshotctl: Control snapshots.\n"
                 "Usage: snapshotctl [action] [flags]\n"
                 "Actions:\n"
                 "  dump\n"
                 "    Print snapshot states.\n"
                 "  merge [--logcat] [--log-to-file] [--report] [--dry-run]\n"
                 "    Initialize merge and wait for it to be completed.\n"
                 "    If --logcat is specified, log to logcat.\n"
                 "    If --log-to-file is specified, log to /data/misc/snapshotctl_log/.\n"
                 "    If both specified, log to both. If none specified, log to stdout.\n"
                 "    If --report is specified, send merge statistics to statsd.\n"
                 "    If --dry-run flag, no real merge operation is is triggered, and\n"
                 "      sample statistics are sent to statsd for testing purpose.\n";
    return EX_USAGE;
}

namespace android {
namespace snapshot {

static SnapshotMergeReport GetDummySnapshotMergeReport() {
    SnapshotMergeReport fake_report;

    fake_report.set_state(UpdateState::MergeCompleted);
    fake_report.set_resume_count(56);

    return fake_report;
}

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
                     O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW | O_SYNC, 0644)));
        if (fd_ == -1) {
            PLOG(ERROR) << "Cannot open persistent log " << ss.str();
            return;
        }
        // Explicitly chmod again because mode in open() may be masked by umask.
        if (fchmod(fd_.get(), 0644) == -1) {
            PLOG(ERROR) << "Cannot chmod 0644 persistent log " << ss.str();
            return;
        }
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
    std::chrono::milliseconds passed_ms;

    bool report_to_statsd = false;
    bool dry_run = false;
    for (int i = 2; i < argc; ++i) {
        if (argv[i] == "--report"s) {
            report_to_statsd = true;
        } else if (argv[i] == "--dry-run"s) {
            dry_run = true;
        }
    }

    // 'snapshotctl merge' is stripped away from arguments to
    // Logger.
    android::base::InitLogging(argv);
    android::base::SetLogger(MergeCmdLogger(argc - 2, argv + 2));

    UpdateState state;
    SnapshotMergeReport merge_report;
    if (dry_run) {
        merge_report = GetDummySnapshotMergeReport();
        state = merge_report.state();
        passed_ms = std::chrono::milliseconds(1234);
    } else {
        auto begin = std::chrono::steady_clock::now();

        state = SnapshotManager::New()->InitiateMergeAndWait(&merge_report);

        // We could wind up in the Unverified state if the device rolled back or
        // hasn't fully rebooted. Ignore this.
        if (state == UpdateState::None || state == UpdateState::Unverified) {
            return true;
        }

        auto end = std::chrono::steady_clock::now();
        passed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - begin);
    }

    if (report_to_statsd) {
        android::util::stats_write(android::util::SNAPSHOT_MERGE_REPORTED,
                                   static_cast<int32_t>(merge_report.state()),
                                   static_cast<int64_t>(passed_ms.count()),
                                   static_cast<int32_t>(merge_report.resume_count()));
    }

    if (state == UpdateState::MergeCompleted) {
        LOG(INFO) << "Snapshot merged in " << passed_ms.count() << " ms.";
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

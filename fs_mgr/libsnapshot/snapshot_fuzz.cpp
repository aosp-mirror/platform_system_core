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

#include <stddef.h>
#include <stdint.h>
#include <sysexits.h>

#include <functional>
#include <sstream>
#include <tuple>

#include <android-base/logging.h>
#include <storage_literals/storage_literals.h>

#include "fuzz_utils.h"
#include "snapshot_fuzz_utils.h"

using android::base::LogId;
using android::base::LogSeverity;
using android::base::SetLogger;
using android::base::StderrLogger;
using android::base::StdioLogger;
using android::fuzz::Bool;
using android::fuzz::FuzzData;
using android::fuzz::FuzzObject;
using android::snapshot::SnapshotFuzzEnv;
using android::snapshot::SnapshotManagerFuzzData;

// Avoid linking to libgsi since it needs disk I/O.
namespace android::gsi {
bool IsGsiRunning() {
    LOG(FATAL) << "Called IsGsiRunning";
    __builtin_unreachable();
}
std::string GetDsuSlot(const std::string& install_dir) {
    LOG(FATAL) << "Called GetDsuSlot(" << install_dir << ")";
    __builtin_unreachable();
}
}  // namespace android::gsi

namespace android::snapshot {

class FuzzSnapshotManager : public FuzzObject<ISnapshotManager, uint8_t> {
  public:
    FuzzSnapshotManager();
};

FuzzSnapshotManager::FuzzSnapshotManager() {
    AddFunction([this]() { (void)get()->BeginUpdate(); });
    AddFunction([this]() { (void)get()->CancelUpdate(); });
    AddFunction<Bool>([this](Bool wipe) { (void)get()->FinishedSnapshotWrites(wipe); });
    AddFunction([this]() { (void)get()->InitiateMerge(); });
    AddFunction<Bool, Bool>([this](auto has_before_cancel, auto fail_before_cancel) {
        std::function<bool()> before_cancel;
        if (has_before_cancel) {
            before_cancel = [=]() { return fail_before_cancel; };
        }
        (void)get()->ProcessUpdateState({}, before_cancel);
    });
    AddFunction<Bool>([this](auto has_progress_arg) {
        double progress;
        (void)get()->GetUpdateState(has_progress_arg ? &progress : nullptr);
    });
    // TODO add CreateUpdateSnapshots according to proto
    // TODO add MapUpdateSnapshot
    // TODO add UnmapUpdateSnapshot using names from the dictionary
    AddFunction([this]() { (void)get()->NeedSnapshotsInFirstStageMount(); });
    // TODO add CreateLogicalAndSnapshotPartitions
    AddFunction<Bool>([this](const Bool& has_callback) {
        std::function<void()> callback;
        if (has_callback) {
            callback = []() {};
        }
        (void)get()->HandleImminentDataWipe(callback);
    });
    AddFunction([this]() { (void)get()->RecoveryCreateSnapshotDevices(); });
    // TODO add RecoveryCreateSnapshotDevices with metadata_device arg
    AddFunction([this]() {
        std::stringstream ss;
        (void)get()->Dump(ss);
    });
    AddFunction([this]() { (void)get()->EnsureMetadataMounted(); });
    AddFunction([this]() { (void)get()->GetSnapshotMergeStatsInstance(); });

    CheckFunctionsSize();
}

// During global init, log all messages to stdio. This is only done once.
int AllowLoggingDuringGlobalInit() {
    SetLogger(&StdioLogger);
    return 0;
}

// Only log fatal messages during tests.
void FatalOnlyLogger(LogId logid, LogSeverity severity, const char* tag, const char* file,
                     unsigned int line, const char* message) {
    if (severity == LogSeverity::FATAL) {
        StderrLogger(logid, severity, tag, file, line, message);
    }
}
// Stop logging (except fatal messages) after global initialization. This is only done once.
int StopLoggingAfterGlobalInit() {
    SetLogger(&FatalOnlyLogger);
    return 0;
}

}  // namespace android::snapshot

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    using namespace android::snapshot;

    [[maybe_unused]] static auto allow_logging = AllowLoggingDuringGlobalInit();
    static SnapshotFuzzEnv env;
    static FuzzSnapshotManager fuzz_snapshot_manager;
    [[maybe_unused]] static auto stop_logging = StopLoggingAfterGlobalInit();

    CHECK(env.InitOk());
    FuzzData fuzz_data(data, size);

    auto snapshot_manager_data = fuzz_data.Consume<SnapshotManagerFuzzData>();
    if (!snapshot_manager_data.has_value()) {
        return 0;
    }
    auto snapshot_manager = env.CreateSnapshotManager(snapshot_manager_data.value());
    CHECK(snapshot_manager);

    fuzz_snapshot_manager.DepleteData(snapshot_manager.get(), &fuzz_data);

    return 0;
}

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
#include <src/libfuzzer/libfuzzer_macro.h>
#include <storage_literals/storage_literals.h>

#include "fuzz_utils.h"
#include "snapshot_fuzz_utils.h"

using android::base::LogId;
using android::base::LogSeverity;
using android::base::SetLogger;
using android::base::StderrLogger;
using android::base::StdioLogger;
using android::fs_mgr::CreateLogicalPartitionParams;
using android::fuzz::CheckedCast;
using android::snapshot::SnapshotFuzzData;
using android::snapshot::SnapshotFuzzEnv;
using chromeos_update_engine::DeltaArchiveManifest;
using google::protobuf::RepeatedPtrField;

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

const SnapshotFuzzData* current_data = nullptr;
const SnapshotTestModule* current_module = nullptr;

SnapshotFuzzEnv* GetSnapshotFuzzEnv();

FUZZ_CLASS(ISnapshotManager, SnapshotManagerAction);

using ProcessUpdateStateArgs = SnapshotManagerAction::Proto::ProcessUpdateStateArgs;
using CreateLogicalAndSnapshotPartitionsArgs =
        SnapshotManagerAction::Proto::CreateLogicalAndSnapshotPartitionsArgs;
using RecoveryCreateSnapshotDevicesArgs =
        SnapshotManagerAction::Proto::RecoveryCreateSnapshotDevicesArgs;

FUZZ_SIMPLE_FUNCTION(SnapshotManagerAction, BeginUpdate);
FUZZ_SIMPLE_FUNCTION(SnapshotManagerAction, CancelUpdate);
FUZZ_SIMPLE_FUNCTION(SnapshotManagerAction, InitiateMerge);
FUZZ_SIMPLE_FUNCTION(SnapshotManagerAction, NeedSnapshotsInFirstStageMount);
FUZZ_SIMPLE_FUNCTION(SnapshotManagerAction, RecoveryCreateSnapshotDevices);
FUZZ_SIMPLE_FUNCTION(SnapshotManagerAction, EnsureMetadataMounted);
FUZZ_SIMPLE_FUNCTION(SnapshotManagerAction, GetSnapshotMergeStatsInstance);

#define SNAPSHOT_FUZZ_FUNCTION(FunctionName, ...) \
    FUZZ_FUNCTION(SnapshotManagerAction, FunctionName, snapshot, ##__VA_ARGS__)

SNAPSHOT_FUZZ_FUNCTION(FinishedSnapshotWrites, bool wipe) {
    (void)snapshot->FinishedSnapshotWrites(wipe);
}

SNAPSHOT_FUZZ_FUNCTION(ProcessUpdateState, const ProcessUpdateStateArgs& args) {
    std::function<bool()> before_cancel;
    if (args.has_before_cancel()) {
        before_cancel = [&]() { return args.fail_before_cancel(); };
    }
    (void)snapshot->ProcessUpdateState({}, before_cancel);
}

SNAPSHOT_FUZZ_FUNCTION(GetUpdateState, bool has_progress_arg) {
    double progress;
    (void)snapshot->GetUpdateState(has_progress_arg ? &progress : nullptr);
}

SNAPSHOT_FUZZ_FUNCTION(HandleImminentDataWipe, bool has_callback) {
    std::function<void()> callback;
    if (has_callback) {
        callback = []() {};
    }
    (void)snapshot->HandleImminentDataWipe(callback);
}

SNAPSHOT_FUZZ_FUNCTION(Dump) {
    std::stringstream ss;
    (void)snapshot->Dump(ss);
}

SNAPSHOT_FUZZ_FUNCTION(CreateUpdateSnapshots, const DeltaArchiveManifest& manifest) {
    (void)snapshot->CreateUpdateSnapshots(manifest);
}

SNAPSHOT_FUZZ_FUNCTION(UnmapUpdateSnapshot, const std::string& name) {
    (void)snapshot->UnmapUpdateSnapshot(name);
}

SNAPSHOT_FUZZ_FUNCTION(CreateLogicalAndSnapshotPartitions,
                       const CreateLogicalAndSnapshotPartitionsArgs& args) {
    const std::string* super;
    if (args.use_correct_super()) {
        super = &GetSnapshotFuzzEnv()->super();
    } else {
        super = &args.super();
    }
    (void)snapshot->CreateLogicalAndSnapshotPartitions(
            *super, std::chrono::milliseconds(args.timeout_millis()));
}

SNAPSHOT_FUZZ_FUNCTION(RecoveryCreateSnapshotDevicesWithMetadata,
                       const RecoveryCreateSnapshotDevicesArgs& args) {
    std::unique_ptr<AutoDevice> device;
    if (args.has_metadata_device_object()) {
        device = std::make_unique<DummyAutoDevice>(args.metadata_mounted());
    }
    (void)snapshot->RecoveryCreateSnapshotDevices(device);
}

SNAPSHOT_FUZZ_FUNCTION(MapUpdateSnapshot, const CreateLogicalPartitionParamsProto& params_proto) {
    auto partition_opener = std::make_unique<TestPartitionOpener>(GetSnapshotFuzzEnv()->super());
    CreateLogicalPartitionParams params;
    if (params_proto.use_correct_super()) {
        params.block_device = GetSnapshotFuzzEnv()->super();
    } else {
        params.block_device = params_proto.block_device();
    }
    if (params_proto.has_metadata_slot()) {
        params.metadata_slot = params_proto.metadata_slot();
    }
    params.partition_name = params_proto.partition_name();
    params.force_writable = params_proto.force_writable();
    params.timeout_ms = std::chrono::milliseconds(params_proto.timeout_millis());
    params.device_name = params_proto.device_name();
    params.partition_opener = partition_opener.get();
    std::string path;
    (void)snapshot->MapUpdateSnapshot(params, &path);
}

SNAPSHOT_FUZZ_FUNCTION(SwitchSlot) {
    (void)snapshot;
    CHECK(current_module != nullptr);
    CHECK(current_module->device_info != nullptr);
    current_module->device_info->SwitchSlot();
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

        // If test fails by a LOG(FATAL) or CHECK(), log the corpus. If it abort()'s, there's
        // nothing else we can do.
        StderrLogger(logid, severity, tag, __FILE__, __LINE__,
                     "Attempting to dump current corpus:");
        if (current_data == nullptr) {
            StderrLogger(logid, severity, tag, __FILE__, __LINE__, "Current corpus is nullptr.");
        } else {
            std::string content;
            if (!google::protobuf::TextFormat::PrintToString(*current_data, &content)) {
                StderrLogger(logid, severity, tag, __FILE__, __LINE__,
                             "Failed to print corpus to string.");
            } else {
                StderrLogger(logid, severity, tag, __FILE__, __LINE__, content.c_str());
            }
        }
    }
}
// Stop logging (except fatal messages) after global initialization. This is only done once.
int StopLoggingAfterGlobalInit() {
    [[maybe_unused]] static protobuf_mutator::protobuf::LogSilencer log_silincer;
    SetLogger(&FatalOnlyLogger);
    return 0;
}

SnapshotFuzzEnv* GetSnapshotFuzzEnv() {
    [[maybe_unused]] static auto allow_logging = AllowLoggingDuringGlobalInit();
    static SnapshotFuzzEnv env;
    [[maybe_unused]] static auto stop_logging = StopLoggingAfterGlobalInit();
    return &env;
}

}  // namespace android::snapshot

DEFINE_PROTO_FUZZER(const SnapshotFuzzData& snapshot_fuzz_data) {
    using namespace android::snapshot;

    current_data = &snapshot_fuzz_data;

    auto env = GetSnapshotFuzzEnv();
    env->CheckSoftReset();

    auto test_module = env->CheckCreateSnapshotManager(snapshot_fuzz_data);
    current_module = &test_module;
    CHECK(test_module.snapshot);

    SnapshotManagerAction::ExecuteAll(test_module.snapshot.get(), snapshot_fuzz_data.actions());

    current_module = nullptr;
    current_data = nullptr;
}

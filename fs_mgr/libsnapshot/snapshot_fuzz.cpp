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
#include <android-base/properties.h>
#include <android-base/result.h>
#include <gtest/gtest.h>
#include <src/libfuzzer/libfuzzer_macro.h>
#include <storage_literals/storage_literals.h>

#include "fuzz_utils.h"
#include "snapshot_fuzz_utils.h"

using android::base::Error;
using android::base::GetBoolProperty;
using android::base::LogId;
using android::base::LogSeverity;
using android::base::ReadFileToString;
using android::base::Result;
using android::base::SetLogger;
using android::base::StderrLogger;
using android::base::StdioLogger;
using android::fs_mgr::CreateLogicalPartitionParams;
using android::fuzz::CheckedCast;
using android::snapshot::SnapshotFuzzData;
using android::snapshot::SnapshotFuzzEnv;
using chromeos_update_engine::DeltaArchiveManifest;
using google::protobuf::FieldDescriptor;
using google::protobuf::Message;
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

#define SNAPSHOT_FUZZ_FUNCTION(FunctionName, ReturnType, ...)                                  \
    FUZZ_FUNCTION(SnapshotManagerAction, FunctionName, ReturnType, ISnapshotManager* snapshot, \
                  ##__VA_ARGS__)

SNAPSHOT_FUZZ_FUNCTION(FinishedSnapshotWrites, bool, bool wipe) {
    return snapshot->FinishedSnapshotWrites(wipe);
}

SNAPSHOT_FUZZ_FUNCTION(ProcessUpdateState, bool, const ProcessUpdateStateArgs& args) {
    std::function<bool()> before_cancel;
    if (args.has_before_cancel()) {
        before_cancel = [&]() { return args.fail_before_cancel(); };
    }
    return snapshot->ProcessUpdateState({}, before_cancel);
}

SNAPSHOT_FUZZ_FUNCTION(GetUpdateState, UpdateState, bool has_progress_arg) {
    double progress;
    return snapshot->GetUpdateState(has_progress_arg ? &progress : nullptr);
}

SNAPSHOT_FUZZ_FUNCTION(HandleImminentDataWipe, bool, bool has_callback) {
    std::function<void()> callback;
    if (has_callback) {
        callback = []() {};
    }
    return snapshot->HandleImminentDataWipe(callback);
}

SNAPSHOT_FUZZ_FUNCTION(Dump, bool) {
    std::stringstream ss;
    return snapshot->Dump(ss);
}

SNAPSHOT_FUZZ_FUNCTION(CreateUpdateSnapshots, bool, const DeltaArchiveManifest& manifest) {
    return snapshot->CreateUpdateSnapshots(manifest);
}

SNAPSHOT_FUZZ_FUNCTION(UnmapUpdateSnapshot, bool, const std::string& name) {
    return snapshot->UnmapUpdateSnapshot(name);
}

SNAPSHOT_FUZZ_FUNCTION(CreateLogicalAndSnapshotPartitions, bool,
                       const CreateLogicalAndSnapshotPartitionsArgs& args) {
    const std::string* super;
    if (args.use_correct_super()) {
        super = &GetSnapshotFuzzEnv()->super();
    } else {
        super = &args.super();
    }
    return snapshot->CreateLogicalAndSnapshotPartitions(
            *super, std::chrono::milliseconds(args.timeout_millis()));
}

SNAPSHOT_FUZZ_FUNCTION(RecoveryCreateSnapshotDevicesWithMetadata, CreateResult,
                       const RecoveryCreateSnapshotDevicesArgs& args) {
    std::unique_ptr<AutoDevice> device;
    if (args.has_metadata_device_object()) {
        device = std::make_unique<NoOpAutoDevice>(args.metadata_mounted());
    }
    return snapshot->RecoveryCreateSnapshotDevices(device);
}

SNAPSHOT_FUZZ_FUNCTION(MapUpdateSnapshot, bool,
                       const CreateLogicalPartitionParamsProto& params_proto) {
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
    return snapshot->MapUpdateSnapshot(params, &path);
}

SNAPSHOT_FUZZ_FUNCTION(SwitchSlot, void) {
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
    (void)GetSnapshotFuzzEnv();
    [[maybe_unused]] static protobuf_mutator::protobuf::LogSilencer log_silencer;
    SetLogger(&FatalOnlyLogger);
    return 0;
}

SnapshotFuzzEnv* GetSnapshotFuzzEnv() {
    [[maybe_unused]] static auto allow_logging = AllowLoggingDuringGlobalInit();
    static SnapshotFuzzEnv env;
    return &env;
}

SnapshotTestModule SetUpTest(const SnapshotFuzzData& snapshot_fuzz_data) {
    current_data = &snapshot_fuzz_data;

    auto env = GetSnapshotFuzzEnv();
    env->CheckSoftReset();

    auto test_module = env->CheckCreateSnapshotManager(snapshot_fuzz_data);
    current_module = &test_module;
    CHECK(test_module.snapshot);
    return test_module;
}

void TearDownTest() {
    current_module = nullptr;
    current_data = nullptr;
}

}  // namespace android::snapshot

DEFINE_PROTO_FUZZER(const SnapshotFuzzData& snapshot_fuzz_data) {
    using namespace android::snapshot;

    [[maybe_unused]] static auto stop_logging = StopLoggingAfterGlobalInit();
    auto test_module = SetUpTest(snapshot_fuzz_data);
    SnapshotManagerAction::ExecuteAll(test_module.snapshot.get(), snapshot_fuzz_data.actions());
    TearDownTest();
}

namespace android::snapshot {

// Work-around to cast a 'void' value to Result<void>.
template <typename T>
struct GoodResult {
    template <typename F>
    static Result<T> Cast(F&& f) {
        return f();
    }
};

template <>
struct GoodResult<void> {
    template <typename F>
    static Result<void> Cast(F&& f) {
        f();
        return {};
    }
};

class LibsnapshotFuzzerTest : public ::testing::Test {
  protected:
    static void SetUpTestCase() {
        // Do initialization once.
        (void)GetSnapshotFuzzEnv();
    }
    void SetUp() override {
        bool is_virtual_ab = GetBoolProperty("ro.virtual_ab.enabled", false);
        if (!is_virtual_ab) GTEST_SKIP() << "Test only runs on Virtual A/B devices.";
    }
    void SetUpFuzzData(const std::string& fn) {
        auto path = android::base::GetExecutableDirectory() + "/corpus/"s + fn;
        std::string proto_text;
        ASSERT_TRUE(ReadFileToString(path, &proto_text));
        snapshot_fuzz_data_ = std::make_unique<SnapshotFuzzData>();
        ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(proto_text,
                                                                  snapshot_fuzz_data_.get()));
        test_module_ = android::snapshot::SetUpTest(*snapshot_fuzz_data_);
    }
    void TearDown() override { android::snapshot::TearDownTest(); }
    template <typename FuzzFunction>
    Result<typename FuzzFunction::ReturnType> Execute(int action_index) {
        if (action_index >= snapshot_fuzz_data_->actions_size()) {
            return Error() << "Index " << action_index << " is out of bounds ("
                           << snapshot_fuzz_data_->actions_size() << " actions in corpus";
        }
        const auto& action_proto = snapshot_fuzz_data_->actions(action_index);
        const auto* field_desc =
                android::fuzz::GetValueFieldDescriptor<typename FuzzFunction::ActionType>(
                        action_proto);
        if (field_desc == nullptr) {
            return Error() << "Action at index " << action_index << " has no value defined.";
        }
        if (FuzzFunction::tag != field_desc->number()) {
            return Error() << "Action at index " << action_index << " is expected to be "
                           << FuzzFunction::name << ", but it is " << field_desc->name()
                           << " in corpus.";
        }
        return GoodResult<typename FuzzFunction::ReturnType>::Cast([&]() {
            return android::fuzz::ActionPerformer<FuzzFunction>::Invoke(test_module_.snapshot.get(),
                                                                        action_proto, field_desc);
        });
    }

    std::unique_ptr<SnapshotFuzzData> snapshot_fuzz_data_;
    SnapshotTestModule test_module_;
};

#define SNAPSHOT_FUZZ_FN_NAME(name) FUZZ_FUNCTION_CLASS_NAME(SnapshotManagerAction, name)

MATCHER_P(ResultIs, expected, "") {
    if (!arg.ok()) {
        *result_listener << arg.error();
        return false;
    }
    *result_listener << "expected: " << expected;
    return arg.value() == expected;
}

#define ASSERT_RESULT_TRUE(actual) ASSERT_THAT(actual, ResultIs(true))

// Check that launch_device.txt is executed correctly.
TEST_F(LibsnapshotFuzzerTest, LaunchDevice) {
    SetUpFuzzData("launch_device.txt");

    int i = 0;
    ASSERT_RESULT_TRUE(Execute<SNAPSHOT_FUZZ_FN_NAME(BeginUpdate)>(i++));
    ASSERT_RESULT_TRUE(Execute<SNAPSHOT_FUZZ_FN_NAME(CreateUpdateSnapshots)>(i++));
    ASSERT_RESULT_TRUE(Execute<SNAPSHOT_FUZZ_FN_NAME(MapUpdateSnapshot)>(i++)) << "sys_b";
    ASSERT_RESULT_TRUE(Execute<SNAPSHOT_FUZZ_FN_NAME(MapUpdateSnapshot)>(i++)) << "vnd_b";
    ASSERT_RESULT_TRUE(Execute<SNAPSHOT_FUZZ_FN_NAME(MapUpdateSnapshot)>(i++)) << "prd_b";
    ASSERT_RESULT_TRUE(Execute<SNAPSHOT_FUZZ_FN_NAME(FinishedSnapshotWrites)>(i++));
    ASSERT_RESULT_TRUE(Execute<SNAPSHOT_FUZZ_FN_NAME(UnmapUpdateSnapshot)>(i++)) << "sys_b";
    ASSERT_RESULT_TRUE(Execute<SNAPSHOT_FUZZ_FN_NAME(UnmapUpdateSnapshot)>(i++)) << "vnd_b";
    ASSERT_RESULT_TRUE(Execute<SNAPSHOT_FUZZ_FN_NAME(UnmapUpdateSnapshot)>(i++)) << "prd_b";
    ASSERT_RESULT_OK(Execute<SNAPSHOT_FUZZ_FN_NAME(SwitchSlot)>(i++));
    ASSERT_EQ("_b", test_module_.device_info->GetSlotSuffix());
    ASSERT_RESULT_TRUE(Execute<SNAPSHOT_FUZZ_FN_NAME(NeedSnapshotsInFirstStageMount)>(i++));
    ASSERT_RESULT_TRUE(Execute<SNAPSHOT_FUZZ_FN_NAME(CreateLogicalAndSnapshotPartitions)>(i++));
    ASSERT_RESULT_TRUE(Execute<SNAPSHOT_FUZZ_FN_NAME(InitiateMerge)>(i++));
    ASSERT_RESULT_TRUE(Execute<SNAPSHOT_FUZZ_FN_NAME(ProcessUpdateState)>(i++));
    ASSERT_EQ(i, snapshot_fuzz_data_->actions_size()) << "Not all actions are executed.";
}

}  // namespace android::snapshot

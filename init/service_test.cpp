/*
 * Copyright (C) 2017 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "service.h"

#include <algorithm>
#include <fstream>
#include <memory>
#include <type_traits>
#include <vector>

#include <gtest/gtest.h>

#include <android-base/file.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <selinux/selinux.h>
#include <sys/signalfd.h>
#include "lmkd_service.h"
#include "reboot.h"
#include "service.h"
#include "service_list.h"
#include "service_parser.h"
#include "util.h"

using ::android::base::ReadFileToString;
using ::android::base::StringPrintf;
using ::android::base::StringReplace;
using ::android::base::unique_fd;
using ::android::base::WriteStringToFd;
using ::android::base::WriteStringToFile;

namespace android {
namespace init {

static std::string GetSecurityContext() {
    char* ctx;
    if (getcon(&ctx) == -1) {
        ADD_FAILURE() << "Failed to call getcon : " << strerror(errno);
    }
    std::string result{ctx};
    freecon(ctx);
    return result;
}

TEST(service, pod_initialized) {
    constexpr auto memory_size = sizeof(Service);
    alignas(alignof(Service)) unsigned char old_memory[memory_size];

    for (std::size_t i = 0; i < memory_size; ++i) {
        old_memory[i] = 0xFF;
    }

    std::vector<std::string> dummy_args{"/bin/test"};
    Service* service_in_old_memory =
        new (old_memory) Service("test_old_memory", nullptr, /*filename=*/"", dummy_args);

    EXPECT_EQ(0U, service_in_old_memory->flags());
    EXPECT_EQ(0, service_in_old_memory->pid());
    EXPECT_EQ(0, service_in_old_memory->crash_count());
    EXPECT_EQ(0U, service_in_old_memory->uid());
    EXPECT_EQ(0U, service_in_old_memory->gid());
    EXPECT_EQ(0, service_in_old_memory->namespace_flags());
    EXPECT_EQ(IoSchedClass_NONE, service_in_old_memory->ioprio_class());
    EXPECT_EQ(0, service_in_old_memory->ioprio_pri());
    EXPECT_EQ(0, service_in_old_memory->priority());
    EXPECT_EQ(DEFAULT_OOM_SCORE_ADJUST, service_in_old_memory->oom_score_adjust());
    EXPECT_FALSE(service_in_old_memory->process_cgroup_empty());

    for (std::size_t i = 0; i < memory_size; ++i) {
        old_memory[i] = 0xFF;
    }

    Service* service_in_old_memory2 = new (old_memory) Service(
            "test_old_memory", 0U, 0U, 0U, std::vector<gid_t>(), 0U, "",
            nullptr, /*filename=*/"", dummy_args);

    EXPECT_EQ(0U, service_in_old_memory2->flags());
    EXPECT_EQ(0, service_in_old_memory2->pid());
    EXPECT_EQ(0, service_in_old_memory2->crash_count());
    EXPECT_EQ(0U, service_in_old_memory2->uid());
    EXPECT_EQ(0U, service_in_old_memory2->gid());
    EXPECT_EQ(0, service_in_old_memory2->namespace_flags());
    EXPECT_EQ(IoSchedClass_NONE, service_in_old_memory2->ioprio_class());
    EXPECT_EQ(0, service_in_old_memory2->ioprio_pri());
    EXPECT_EQ(0, service_in_old_memory2->priority());
    EXPECT_EQ(DEFAULT_OOM_SCORE_ADJUST, service_in_old_memory2->oom_score_adjust());
    EXPECT_FALSE(service_in_old_memory->process_cgroup_empty());
}

TEST(service, make_temporary_oneshot_service_invalid_syntax) {
    std::vector<std::string> args;
    // Nothing.
    ASSERT_FALSE(Service::MakeTemporaryOneshotService(args).ok());

    // No arguments to 'exec'.
    args.push_back("exec");
    ASSERT_FALSE(Service::MakeTemporaryOneshotService(args).ok());

    // No command in "exec --".
    args.push_back("--");
    ASSERT_FALSE(Service::MakeTemporaryOneshotService(args).ok());
}

TEST(service, make_temporary_oneshot_service_too_many_supplementary_gids) {
    std::vector<std::string> args;
    args.push_back("exec");
    args.push_back("seclabel");
    args.push_back("root");  // uid.
    args.push_back("root");  // gid.
    for (int i = 0; i < NR_SVC_SUPP_GIDS; ++i) {
        args.push_back("root");  // Supplementary gid.
    }
    args.push_back("--");
    args.push_back("/system/bin/id");
    ASSERT_FALSE(Service::MakeTemporaryOneshotService(args).ok());
}

static void Test_make_temporary_oneshot_service(bool dash_dash, bool seclabel, bool uid, bool gid,
                                                bool supplementary_gids) {
    std::vector<std::string> args;
    args.push_back("exec");
    if (seclabel) {
        args.push_back("u:r:su:s0");  // seclabel
        if (uid) {
            args.push_back("log");  // uid
            if (gid) {
                args.push_back("shell");  // gid
                if (supplementary_gids) {
                    args.push_back("system");  // supplementary gid 0
                    args.push_back("adb");     // supplementary gid 1
                }
            }
        }
    }
    if (dash_dash) {
        args.push_back("--");
    }
    args.push_back("/system/bin/toybox");
    args.push_back("id");
    auto service_ret = Service::MakeTemporaryOneshotService(args);
    ASSERT_RESULT_OK(service_ret);
    auto svc = std::move(*service_ret);

    if (seclabel) {
        ASSERT_EQ("u:r:su:s0", svc->seclabel());
    } else {
        ASSERT_EQ("", svc->seclabel());
    }
    if (uid) {
        auto decoded_uid = DecodeUid("log");
        ASSERT_RESULT_OK(decoded_uid);
        ASSERT_EQ(*decoded_uid, svc->uid());
    } else {
        ASSERT_EQ(0U, svc->uid());
    }
    if (gid) {
        auto decoded_uid = DecodeUid("shell");
        ASSERT_RESULT_OK(decoded_uid);
        ASSERT_EQ(*decoded_uid, svc->gid());
    } else {
        ASSERT_EQ(0U, svc->gid());
    }
    if (supplementary_gids) {
        ASSERT_EQ(2U, svc->supp_gids().size());

        auto decoded_uid = DecodeUid("system");
        ASSERT_RESULT_OK(decoded_uid);
        ASSERT_EQ(*decoded_uid, svc->supp_gids()[0]);

        decoded_uid = DecodeUid("adb");
        ASSERT_RESULT_OK(decoded_uid);
        ASSERT_EQ(*decoded_uid, svc->supp_gids()[1]);
    } else {
        ASSERT_EQ(0U, svc->supp_gids().size());
    }

    ASSERT_EQ(static_cast<std::size_t>(2), svc->args().size());
    ASSERT_EQ("/system/bin/toybox", svc->args()[0]);
    ASSERT_EQ("id", svc->args()[1]);
}

TEST(service, make_temporary_oneshot_service_with_everything) {
    Test_make_temporary_oneshot_service(true, true, true, true, true);
}

TEST(service, make_temporary_oneshot_service_with_seclabel_uid_gid) {
    Test_make_temporary_oneshot_service(true, true, true, true, false);
}

TEST(service, make_temporary_oneshot_service_with_seclabel_uid) {
    Test_make_temporary_oneshot_service(true, true, true, false, false);
}

TEST(service, make_temporary_oneshot_service_with_seclabel) {
    Test_make_temporary_oneshot_service(true, true, false, false, false);
}

TEST(service, make_temporary_oneshot_service_with_just_command) {
    Test_make_temporary_oneshot_service(true, false, false, false, false);
}

TEST(service, make_temporary_oneshot_service_with_just_command_no_dash) {
    Test_make_temporary_oneshot_service(false, false, false, false, false);
}

// Returns the path in the v2 cgroup hierarchy for a given process in the format /uid_%d/pid_%d.
static std::string CgroupPath(pid_t pid) {
    std::string cgroup_path = StringPrintf("/proc/%d/cgroup", pid);
    std::ifstream is(cgroup_path, std::ios::in);
    std::string line;
    while (std::getline(is, line)) {
        if (line.substr(0, 3) == "0::") {
            return line.substr(3);
        }
    }
    return {};
}

class ServiceStopTest : public testing::TestWithParam<bool> {};

// Before November 2023, processes that were migrated to another v2 cgroup were ignored by
// Service::Stop() if their uid_%d/pid_%d cgroup directory got removed. This test, if run with the
// parameter set to 'true', verifies that such services are stopped.
TEST_P(ServiceStopTest, stop) {
    static constexpr std::string_view kServiceName = "ServiceA";
    static constexpr std::string_view kScriptTemplate = R"init(
service $name /system/bin/yes
    user shell
    group shell
    seclabel $selabel
)init";

    std::string script = StringReplace(StringReplace(kScriptTemplate, "$name", kServiceName, false),
                                       "$selabel", GetSecurityContext(), false);
    ServiceList& service_list = ServiceList::GetInstance();
    Parser parser;
    parser.AddSectionParser("service",
                            std::make_unique<ServiceParser>(&service_list, nullptr, std::nullopt));

    TemporaryFile tf;
    ASSERT_GE(tf.fd, 0);
    ASSERT_TRUE(WriteStringToFd(script, tf.fd));
    ASSERT_TRUE(parser.ParseConfig(tf.path));

    Service* const service = ServiceList::GetInstance().FindService(kServiceName);
    ASSERT_NE(service, nullptr);
    ASSERT_RESULT_OK(service->Start());
    ASSERT_TRUE(service->IsRunning());
    if (GetParam()) {
        const pid_t pid = service->pid();
        const std::string cgroup_path = CgroupPath(pid);
        EXPECT_NE(cgroup_path, "");
        EXPECT_NE(cgroup_path, "/");
        const std::string pid_str = std::to_string(pid);
        EXPECT_TRUE(WriteStringToFile(pid_str, "/sys/fs/cgroup/cgroup.procs"));
        EXPECT_EQ(CgroupPath(pid), "/");
        EXPECT_EQ(rmdir(("/sys/fs/cgroup" + cgroup_path).c_str()), 0);
    }
    EXPECT_EQ(0, StopServicesAndLogViolations({service->name()}, 10s, /*terminate=*/true));
    ServiceList::GetInstance().RemoveService(*service);
}

INSTANTIATE_TEST_SUITE_P(service, ServiceStopTest, testing::Values(false, true));

}  // namespace init
}  // namespace android

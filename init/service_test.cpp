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
#include <memory>
#include <type_traits>
#include <vector>

#include <gtest/gtest.h>

#include "util.h"

namespace android {
namespace init {

TEST(service, pod_initialized) {
    constexpr auto memory_size = sizeof(Service);
    alignas(alignof(Service)) char old_memory[memory_size];

    for (std::size_t i = 0; i < memory_size; ++i) {
        old_memory[i] = 0xFF;
    }

    std::vector<std::string> dummy_args{"/bin/test"};
    Service* service_in_old_memory =
        new (old_memory) Service("test_old_memory", nullptr, dummy_args);

    EXPECT_EQ(0U, service_in_old_memory->flags());
    EXPECT_EQ(0, service_in_old_memory->pid());
    EXPECT_EQ(0, service_in_old_memory->crash_count());
    EXPECT_EQ(0U, service_in_old_memory->uid());
    EXPECT_EQ(0U, service_in_old_memory->gid());
    EXPECT_EQ(0U, service_in_old_memory->namespace_flags());
    EXPECT_EQ(IoSchedClass_NONE, service_in_old_memory->ioprio_class());
    EXPECT_EQ(0, service_in_old_memory->ioprio_pri());
    EXPECT_EQ(0, service_in_old_memory->priority());
    EXPECT_EQ(-1000, service_in_old_memory->oom_score_adjust());
    EXPECT_FALSE(service_in_old_memory->process_cgroup_empty());

    for (std::size_t i = 0; i < memory_size; ++i) {
        old_memory[i] = 0xFF;
    }

    Service* service_in_old_memory2 = new (old_memory) Service(
        "test_old_memory", 0U, 0U, 0U, std::vector<gid_t>(), CapSet(), 0U, "", nullptr, dummy_args);

    EXPECT_EQ(0U, service_in_old_memory2->flags());
    EXPECT_EQ(0, service_in_old_memory2->pid());
    EXPECT_EQ(0, service_in_old_memory2->crash_count());
    EXPECT_EQ(0U, service_in_old_memory2->uid());
    EXPECT_EQ(0U, service_in_old_memory2->gid());
    EXPECT_EQ(0U, service_in_old_memory2->namespace_flags());
    EXPECT_EQ(IoSchedClass_NONE, service_in_old_memory2->ioprio_class());
    EXPECT_EQ(0, service_in_old_memory2->ioprio_pri());
    EXPECT_EQ(0, service_in_old_memory2->priority());
    EXPECT_EQ(-1000, service_in_old_memory2->oom_score_adjust());
    EXPECT_FALSE(service_in_old_memory->process_cgroup_empty());
}

TEST(service, make_temporary_oneshot_service_invalid_syntax) {
    std::vector<std::string> args;
    // Nothing.
    ASSERT_EQ(nullptr, Service::MakeTemporaryOneshotService(args));

    // No arguments to 'exec'.
    args.push_back("exec");
    ASSERT_EQ(nullptr, Service::MakeTemporaryOneshotService(args));

    // No command in "exec --".
    args.push_back("--");
    ASSERT_EQ(nullptr, Service::MakeTemporaryOneshotService(args));
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
    ASSERT_EQ(nullptr, Service::MakeTemporaryOneshotService(args));
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
    auto svc = Service::MakeTemporaryOneshotService(args);
    ASSERT_NE(nullptr, svc);

    if (seclabel) {
        ASSERT_EQ("u:r:su:s0", svc->seclabel());
    } else {
        ASSERT_EQ("", svc->seclabel());
    }
    if (uid) {
        auto decoded_uid = DecodeUid("log");
        ASSERT_TRUE(decoded_uid);
        ASSERT_EQ(*decoded_uid, svc->uid());
    } else {
        ASSERT_EQ(0U, svc->uid());
    }
    if (gid) {
        auto decoded_uid = DecodeUid("shell");
        ASSERT_TRUE(decoded_uid);
        ASSERT_EQ(*decoded_uid, svc->gid());
    } else {
        ASSERT_EQ(0U, svc->gid());
    }
    if (supplementary_gids) {
        ASSERT_EQ(2U, svc->supp_gids().size());

        auto decoded_uid = DecodeUid("system");
        ASSERT_TRUE(decoded_uid);
        ASSERT_EQ(*decoded_uid, svc->supp_gids()[0]);

        decoded_uid = DecodeUid("adb");
        ASSERT_TRUE(decoded_uid);
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

}  // namespace init
}  // namespace android

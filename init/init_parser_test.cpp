/*
 * Copyright (C) 2015 The Android Open Source Project
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

#include "init_parser.h"

#include "init.h"
#include "service.h"

#include <gtest/gtest.h>

#include <string>
#include <vector>

TEST(init_parser, make_exec_oneshot_service_invalid_syntax) {
    ServiceManager& sm = ServiceManager::GetInstance();
    std::vector<std::string> args;
    // Nothing.
    ASSERT_EQ(nullptr, sm.MakeExecOneshotService(args));

    // No arguments to 'exec'.
    args.push_back("exec");
    ASSERT_EQ(nullptr, sm.MakeExecOneshotService(args));

    // No command in "exec --".
    args.push_back("--");
    ASSERT_EQ(nullptr, sm.MakeExecOneshotService(args));
}

TEST(init_parser, make_exec_oneshot_service_too_many_supplementary_gids) {
    ServiceManager& sm = ServiceManager::GetInstance();
    std::vector<std::string> args;
    args.push_back("exec");
    args.push_back("seclabel");
    args.push_back("root"); // uid.
    args.push_back("root"); // gid.
    for (int i = 0; i < NR_SVC_SUPP_GIDS; ++i) {
        args.push_back("root"); // Supplementary gid.
    }
    args.push_back("--");
    args.push_back("/system/bin/id");
    ASSERT_EQ(nullptr, sm.MakeExecOneshotService(args));
}

static void Test_make_exec_oneshot_service(bool dash_dash, bool seclabel, bool uid,
                                           bool gid, bool supplementary_gids) {
    ServiceManager& sm = ServiceManager::GetInstance();
    std::vector<std::string> args;
    args.push_back("exec");
    if (seclabel) {
        args.push_back("u:r:su:s0"); // seclabel
        if (uid) {
            args.push_back("log");      // uid
            if (gid) {
                args.push_back("shell");     // gid
                if (supplementary_gids) {
                    args.push_back("system");    // supplementary gid 0
                    args.push_back("adb");       // supplementary gid 1
                }
            }
        }
    }
    if (dash_dash) {
        args.push_back("--");
    }
    args.push_back("/system/bin/toybox");
    args.push_back("id");
    Service* svc = sm.MakeExecOneshotService(args);
    ASSERT_NE(nullptr, svc);

    if (seclabel) {
        ASSERT_EQ("u:r:su:s0", svc->seclabel());
    } else {
        ASSERT_EQ("", svc->seclabel());
    }
    if (uid) {
        uid_t decoded_uid;
        std::string err;
        ASSERT_TRUE(DecodeUid("log", &decoded_uid, &err));
        ASSERT_EQ(decoded_uid, svc->uid());
    } else {
        ASSERT_EQ(0U, svc->uid());
    }
    if (gid) {
        uid_t decoded_uid;
        std::string err;
        ASSERT_TRUE(DecodeUid("shell", &decoded_uid, &err));
        ASSERT_EQ(decoded_uid, svc->gid());
    } else {
        ASSERT_EQ(0U, svc->gid());
    }
    if (supplementary_gids) {
        ASSERT_EQ(2U, svc->supp_gids().size());
        uid_t decoded_uid;
        std::string err;
        ASSERT_TRUE(DecodeUid("system", &decoded_uid, &err));
        ASSERT_EQ(decoded_uid, svc->supp_gids()[0]);
        ASSERT_TRUE(DecodeUid("adb", &decoded_uid, &err));
        ASSERT_EQ(decoded_uid, svc->supp_gids()[1]);
    } else {
        ASSERT_EQ(0U, svc->supp_gids().size());
    }

    ASSERT_EQ(static_cast<std::size_t>(2), svc->args().size());
    ASSERT_EQ("/system/bin/toybox", svc->args()[0]);
    ASSERT_EQ("id", svc->args()[1]);
}

TEST(init_parser, make_exec_oneshot_service_with_everything) {
    Test_make_exec_oneshot_service(true, true, true, true, true);
}

TEST(init_parser, make_exec_oneshot_service_with_seclabel_uid_gid) {
    Test_make_exec_oneshot_service(true, true, true, true, false);
}

TEST(init_parser, make_exec_oneshot_service_with_seclabel_uid) {
    Test_make_exec_oneshot_service(true, true, true, false, false);
}

TEST(init_parser, make_exec_oneshot_service_with_seclabel) {
    Test_make_exec_oneshot_service(true, true, false, false, false);
}

TEST(init_parser, make_exec_oneshot_service_with_just_command) {
    Test_make_exec_oneshot_service(true, false, false, false, false);
}

TEST(init_parser, make_exec_oneshot_service_with_just_command_no_dash) {
    Test_make_exec_oneshot_service(false, false, false, false, false);
}

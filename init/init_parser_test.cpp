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
#include "util.h"

#include <errno.h>
#include <gtest/gtest.h>

TEST(init_parser, make_exec_oneshot_service_invalid_syntax) {
    char* argv[10];
    memset(argv, 0, sizeof(argv));

    // Nothing.
    ASSERT_EQ(nullptr, make_exec_oneshot_service(0, argv));

    // No arguments to 'exec'.
    argv[0] = const_cast<char*>("exec");
    ASSERT_EQ(nullptr, make_exec_oneshot_service(1, argv));

    // No command in "exec --".
    argv[1] = const_cast<char*>("--");
    ASSERT_EQ(nullptr, make_exec_oneshot_service(2, argv));
}

TEST(init_parser, make_exec_oneshot_service_too_many_supplementary_gids) {
    int argc = 0;
    char* argv[4 + NR_SVC_SUPP_GIDS + 3];
    argv[argc++] = const_cast<char*>("exec");
    argv[argc++] = const_cast<char*>("seclabel");
    argv[argc++] = const_cast<char*>("root"); // uid.
    argv[argc++] = const_cast<char*>("root"); // gid.
    for (int i = 0; i < NR_SVC_SUPP_GIDS; ++i) {
        argv[argc++] = const_cast<char*>("root"); // Supplementary gid.
    }
    argv[argc++] = const_cast<char*>("--");
    argv[argc++] = const_cast<char*>("/system/bin/id");
    argv[argc] = nullptr;
    ASSERT_EQ(nullptr, make_exec_oneshot_service(argc, argv));
}

static void Test_make_exec_oneshot_service(bool dash_dash, bool seclabel, bool uid, bool gid, bool supplementary_gids) {
    int argc = 0;
    char* argv[10];
    argv[argc++] = const_cast<char*>("exec");
    if (seclabel) {
        argv[argc++] = const_cast<char*>("u:r:su:s0"); // seclabel
        if (uid) {
            argv[argc++] = const_cast<char*>("log");      // uid
            if (gid) {
                argv[argc++] = const_cast<char*>("shell");     // gid
                if (supplementary_gids) {
                    argv[argc++] = const_cast<char*>("system");    // supplementary gid 0
                    argv[argc++] = const_cast<char*>("adb");       // supplementary gid 1
                }
            }
        }
    }
    if (dash_dash) {
        argv[argc++] = const_cast<char*>("--");
    }
    argv[argc++] = const_cast<char*>("/system/bin/toybox");
    argv[argc++] = const_cast<char*>("id");
    argv[argc] = nullptr;
    service* svc = make_exec_oneshot_service(argc, argv);
    ASSERT_NE(nullptr, svc);

    if (seclabel) {
        ASSERT_STREQ("u:r:su:s0", svc->seclabel);
    } else {
        ASSERT_EQ(nullptr, svc->seclabel);
    }
    if (uid) {
        ASSERT_EQ(decode_uid("log"), svc->uid);
    } else {
        ASSERT_EQ(0U, svc->uid);
    }
    if (gid) {
        ASSERT_EQ(decode_uid("shell"), svc->gid);
    } else {
        ASSERT_EQ(0U, svc->gid);
    }
    if (supplementary_gids) {
        ASSERT_EQ(2U, svc->nr_supp_gids);
        ASSERT_EQ(decode_uid("system"), svc->supp_gids[0]);
        ASSERT_EQ(decode_uid("adb"), svc->supp_gids[1]);
    } else {
        ASSERT_EQ(0U, svc->nr_supp_gids);
    }

    ASSERT_EQ(2, svc->nargs);
    ASSERT_EQ("/system/bin/toybox", svc->args[0]);
    ASSERT_EQ("id", svc->args[1]);
    ASSERT_EQ(nullptr, svc->args[2]);
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

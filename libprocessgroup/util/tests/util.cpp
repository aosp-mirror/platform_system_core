/*
 * Copyright (C) 2024 The Android Open Source Project
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

#include <processgroup/util.h>

#include "gtest/gtest.h"

using util::GetCgroupDepth;

TEST(EmptyInputs, bothEmpty) {
    EXPECT_EQ(GetCgroupDepth({}, {}), 0);
}

TEST(EmptyInputs, rootEmpty) {
    EXPECT_EQ(GetCgroupDepth({}, "foo"), 0);
}

TEST(EmptyInputs, pathEmpty) {
    EXPECT_EQ(GetCgroupDepth("foo", {}), 0);
}

TEST(InvalidInputs, pathNotInRoot) {
    EXPECT_EQ(GetCgroupDepth("foo", "bar"), 0);
}

TEST(InvalidInputs, rootLargerThanPath) {
    EXPECT_EQ(GetCgroupDepth("/a/long/path", "/short"), 0);
}

TEST(InvalidInputs, pathLargerThanRoot) {
    EXPECT_EQ(GetCgroupDepth("/short", "/a/long/path"), 0);
}

TEST(InvalidInputs, missingSeparator) {
    EXPECT_EQ(GetCgroupDepth("/controller/root", "/controller/rootcgroup"), 0);
}

TEST(ExtraSeparators, root) {
    EXPECT_EQ(GetCgroupDepth("///sys/fs/cgroup", "/sys/fs/cgroup/a/b/c"), 3);
    EXPECT_EQ(GetCgroupDepth("/sys///fs/cgroup", "/sys/fs/cgroup/a/b/c"), 3);
    EXPECT_EQ(GetCgroupDepth("/sys/fs///cgroup", "/sys/fs/cgroup/a/b/c"), 3);

    EXPECT_EQ(GetCgroupDepth("/sys/fs/cgroup", "///sys/fs/cgroup/a/b/c"), 3);
    EXPECT_EQ(GetCgroupDepth("/sys/fs/cgroup", "/sys///fs/cgroup/a/b/c"), 3);
    EXPECT_EQ(GetCgroupDepth("/sys/fs/cgroup", "/sys/fs///cgroup/a/b/c"), 3);
    EXPECT_EQ(GetCgroupDepth("/sys/fs/cgroup", "/sys/fs/cgroup///a/b/c"), 3);
    EXPECT_EQ(GetCgroupDepth("/sys/fs/cgroup", "/sys/fs/cgroup/a///b/c"), 3);
    EXPECT_EQ(GetCgroupDepth("/sys/fs/cgroup", "/sys/fs/cgroup/a/b///c"), 3);
}

TEST(SeparatorEndings, rootEndsInSeparator) {
    EXPECT_EQ(GetCgroupDepth("/sys/fs/cgroup/", "/sys/fs/cgroup/a/b"), 2);
    EXPECT_EQ(GetCgroupDepth("/sys/fs/cgroup///", "/sys/fs/cgroup/a/b"), 2);
    EXPECT_EQ(GetCgroupDepth("/sys/fs/cgroup/", "/sys/fs/cgroup/a/b/"), 2);
    EXPECT_EQ(GetCgroupDepth("/sys/fs/cgroup///", "/sys/fs/cgroup/a/b/"), 2);
}

TEST(SeparatorEndings, pathEndsInSeparator) {
    EXPECT_EQ(GetCgroupDepth("/sys/fs/cgroup", "/sys/fs/cgroup/a/b/"), 2);
    EXPECT_EQ(GetCgroupDepth("/sys/fs/cgroup", "/sys/fs/cgroup/a/b///"), 2);
    EXPECT_EQ(GetCgroupDepth("/sys/fs/cgroup/", "/sys/fs/cgroup/a/b/"), 2);
    EXPECT_EQ(GetCgroupDepth("/sys/fs/cgroup/", "/sys/fs/cgroup/a/b///"), 2);
}

TEST(ValidInputs, rootHasZeroDepth) {
    EXPECT_EQ(GetCgroupDepth("/sys/fs/cgroup", "/sys/fs/cgroup"), 0);
    EXPECT_EQ(GetCgroupDepth("/sys/fs/cgroup/", "/sys/fs/cgroup"), 0);
    EXPECT_EQ(GetCgroupDepth("/sys/fs/cgroup", "/sys/fs/cgroup/"), 0);
    EXPECT_EQ(GetCgroupDepth("/sys/fs/cgroup/", "/sys/fs/cgroup/"), 0);
}

TEST(ValidInputs, atLeastDepth10) {
    EXPECT_EQ(GetCgroupDepth("/sys/fs/cgroup", "/sys/fs/cgroup/a/b/c/d/e/f/g/h/i/j"), 10);
}

TEST(ValidInputs, androidCgroupNames) {
    EXPECT_EQ(GetCgroupDepth("/sys/fs/cgroup", "/sys/fs/cgroup/system/uid_0/pid_1000"), 3);
    EXPECT_EQ(GetCgroupDepth("/sys/fs/cgroup", "/sys/fs/cgroup/uid_0/pid_1000"), 2);

    EXPECT_EQ(GetCgroupDepth("/sys/fs/cgroup", "/sys/fs/cgroup/apps/uid_100000/pid_1000"), 3);
    EXPECT_EQ(GetCgroupDepth("/sys/fs/cgroup", "/sys/fs/cgroup/uid_100000/pid_1000"), 2);

    EXPECT_EQ(GetCgroupDepth("/sys/fs/cgroup", "/sys/fs/cgroup/apps"), 1);
    EXPECT_EQ(GetCgroupDepth("/sys/fs/cgroup", "/sys/fs/cgroup/system"), 1);
}

TEST(ValidInputs, androidCgroupNames_nonDefaultRoot) {
    EXPECT_EQ(GetCgroupDepth("/custom/root", "/custom/root/system/uid_0/pid_1000"), 3);
    EXPECT_EQ(GetCgroupDepth("/custom/root", "/custom/root/uid_0/pid_1000"), 2);

    EXPECT_EQ(GetCgroupDepth("/custom/root", "/custom/root/apps/uid_100000/pid_1000"), 3);
    EXPECT_EQ(GetCgroupDepth("/custom/root", "/custom/root/uid_100000/pid_1000"), 2);

    EXPECT_EQ(GetCgroupDepth("/custom/root", "/custom/root/apps"), 1);
    EXPECT_EQ(GetCgroupDepth("/custom/root", "/custom/root/system"), 1);
}

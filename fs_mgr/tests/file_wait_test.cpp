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

#include <chrono>
#include <string>
#include <thread>

#include <android-base/file.h>
#include <android-base/unique_fd.h>
#include <fs_mgr/file_wait.h>
#include <gtest/gtest.h>

using namespace std::literals;
using android::base::unique_fd;
using android::fs_mgr::WaitForFile;
using android::fs_mgr::WaitForFileDeleted;

class FileWaitTest : public ::testing::Test {
  protected:
    void SetUp() override {
        const ::testing::TestInfo* tinfo = ::testing::UnitTest::GetInstance()->current_test_info();
        test_file_ = temp_dir_.path + "/"s + tinfo->name();
    }

    void TearDown() override { unlink(test_file_.c_str()); }

    TemporaryDir temp_dir_;
    std::string test_file_;
};

TEST_F(FileWaitTest, FileExists) {
    unique_fd fd(open(test_file_.c_str(), O_CREAT | O_TRUNC | O_RDWR, 0700));
    ASSERT_GE(fd, 0);

    ASSERT_TRUE(WaitForFile(test_file_, 500ms));
    ASSERT_FALSE(WaitForFileDeleted(test_file_, 500ms));
}

TEST_F(FileWaitTest, FileDoesNotExist) {
    ASSERT_FALSE(WaitForFile(test_file_, 500ms));
    ASSERT_TRUE(WaitForFileDeleted(test_file_, 500ms));
}

TEST_F(FileWaitTest, CreateAsync) {
    std::thread thread([this] {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        unique_fd fd(open(test_file_.c_str(), O_CREAT | O_TRUNC | O_RDWR, 0700));
    });
    EXPECT_TRUE(WaitForFile(test_file_, 3s));
    thread.join();
}

TEST_F(FileWaitTest, CreateOtherAsync) {
    std::thread thread([this] {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        unique_fd fd(open(test_file_.c_str(), O_CREAT | O_TRUNC | O_RDWR, 0700));
    });
    EXPECT_FALSE(WaitForFile(test_file_ + ".wontexist", 2s));
    thread.join();
}

TEST_F(FileWaitTest, DeleteAsync) {
    // Note: need to close the file, otherwise inotify considers it not deleted.
    {
        unique_fd fd(open(test_file_.c_str(), O_CREAT | O_TRUNC | O_RDWR, 0700));
        ASSERT_GE(fd, 0);
    }

    std::thread thread([this] {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        unlink(test_file_.c_str());
    });
    EXPECT_TRUE(WaitForFileDeleted(test_file_, 3s));
    thread.join();
}

TEST_F(FileWaitTest, BadPath) {
    ASSERT_FALSE(WaitForFile("/this/path/does/not/exist", 5ms));
    EXPECT_EQ(errno, ENOENT);
}

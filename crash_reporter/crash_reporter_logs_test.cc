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

#include <string>

#include <base/files/file_path.h>
#include <brillo/key_value_store.h>
#include <gtest/gtest.h>

namespace {

// Name of the checked-in configuration file containing log-collection commands.
const char kConfigFile[] = "/system/etc/crash_reporter_logs.conf";

// Signature name for crash_reporter user collection.
// kConfigFile is expected to contain this entry.
const char kUserCollectorSignature[] = "crash_reporter-user-collection";

}  // namespace

// Tests that the config file is parsable and that Chrome is listed.
TEST(CrashReporterLogsTest, ReadConfig) {
  brillo::KeyValueStore store;
  ASSERT_TRUE(store.Load(base::FilePath(kConfigFile)));
  std::string command;
  EXPECT_TRUE(store.GetString(kUserCollectorSignature, &command));
  EXPECT_FALSE(command.empty());
}

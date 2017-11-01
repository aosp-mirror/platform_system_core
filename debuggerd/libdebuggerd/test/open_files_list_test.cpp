/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <string>

#include <gtest/gtest.h>

#include "android-base/test_utils.h"

#include "libdebuggerd/open_files_list.h"

// Check that we can produce a list of open files for the current process, and
// that it includes a known open file.
TEST(OpenFilesListTest, BasicTest) {
  // Open a temporary file that we can check for in the list of open files.
  TemporaryFile tf;

  // Get the list of open files for this process.
  OpenFilesList list;
  populate_open_files_list(getpid(), &list);

  // Verify our open file is in the list.
  bool found = false;
  for (auto&  file : list) {
    if (file.first == tf.fd) {
      EXPECT_EQ(file.second, std::string(tf.path));
      found = true;
      break;
    }
  }
  EXPECT_TRUE(found);
}

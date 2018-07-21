/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include "android-base/unique_fd.h"

#include <gtest/gtest.h>

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

using android::base::unique_fd;

TEST(unique_fd, unowned_close) {
#if defined(__BIONIC__)
  unique_fd fd(open("/dev/null", O_RDONLY));
  EXPECT_DEATH(close(fd.get()), "incorrect tag");
#endif
}

TEST(unique_fd, untag_on_release) {
  unique_fd fd(open("/dev/null", O_RDONLY));
  close(fd.release());
}

TEST(unique_fd, move) {
  unique_fd fd(open("/dev/null", O_RDONLY));
  unique_fd fd_moved = std::move(fd);
  ASSERT_EQ(-1, fd.get());
  ASSERT_GT(fd_moved.get(), -1);
}

TEST(unique_fd, unowned_close_after_move) {
#if defined(__BIONIC__)
  unique_fd fd(open("/dev/null", O_RDONLY));
  unique_fd fd_moved = std::move(fd);
  ASSERT_EQ(-1, fd.get());
  ASSERT_GT(fd_moved.get(), -1);
  EXPECT_DEATH(close(fd_moved.get()), "incorrect tag");
#endif
}

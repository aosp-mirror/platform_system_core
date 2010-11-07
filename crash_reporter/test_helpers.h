// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef _CRASH_REPORTER_TEST_HELPERS_H_
#define _CRASH_REPORTER_TEST_HELPERS_H_

#include "gtest/gtest.h"

inline void ExpectFileEquals(const char *golden,
                             const char *file_path) {
  std::string contents;
  EXPECT_TRUE(file_util::ReadFileToString(FilePath(file_path),
                                          &contents));
  EXPECT_EQ(golden, contents);
}

#endif  // _CRASH_REPORTER_TEST_HELPERS_H_

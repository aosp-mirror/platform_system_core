// Copyright (c) 2013 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef _CRASH_REPORTER_CHROME_COLLECTOR_H_
#define _CRASH_REPORTER_CHROME_COLLECTOR_H_

#include <string>

#include "base/file_path.h"
#include "crash-reporter/crash_collector.h"
#include "gtest/gtest_prod.h"  // for FRIEND_TEST

class SystemLogging;

// Chrome crash collector.
class ChromeCollector : public CrashCollector {
 public:
  ChromeCollector();
  virtual ~ChromeCollector();

  // Handle a specific chrome crash.  Returns true on success.
  bool HandleCrash(const std::string &file_path, const std::string &pid_string,
                   const std::string &uid_string, const std::string &exe_name);

 private:
  friend class ChromeCollectorTest;
  FRIEND_TEST(ChromeCollectorTest, GoodValues);
  FRIEND_TEST(ChromeCollectorTest, BadValues);
  FRIEND_TEST(ChromeCollectorTest, Newlines);
  FRIEND_TEST(ChromeCollectorTest, File);

  // Crashes are expected to be in a TLV-style format of:
  // <name>:<length>:<value>
  // Length is encoded as a decimal number. It can be zero, but must consist of
  // at least one character
  // For file values, name actually contains both a description and a filename,
  // in a fixed format of: <description>"; filename="<filename>"
  bool ParseCrashLog(const std::string &data, const base::FilePath &dir,
                     const base::FilePath &minidump,
                     const std::string &basename);
};

#endif

// Copyright (c) 2013 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRASH_REPORTER_CHROME_COLLECTOR_H_
#define CRASH_REPORTER_CHROME_COLLECTOR_H_

#include <map>
#include <string>

#include <base/files/file_path.h>
#include <base/macros.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST

#include "crash-reporter/crash_collector.h"
#include "debugd/dbus-proxies.h"

class SystemLogging;

// Chrome crash collector.
class ChromeCollector : public CrashCollector {
 public:
  ChromeCollector();
  ~ChromeCollector() override;

  // Magic string to let Chrome know the crash report succeeded.
  static const char kSuccessMagic[];

  // Handle a specific chrome crash.  Returns true on success.
  bool HandleCrash(const base::FilePath &file_path,
                   const std::string &pid_string,
                   const std::string &uid_string,
                   const std::string &exe_name);

 protected:
  void SetUpDBus() override;

 private:
  friend class ChromeCollectorTest;
  FRIEND_TEST(ChromeCollectorTest, GoodValues);
  FRIEND_TEST(ChromeCollectorTest, BadValues);
  FRIEND_TEST(ChromeCollectorTest, Newlines);
  FRIEND_TEST(ChromeCollectorTest, File);
  FRIEND_TEST(ChromeCollectorTest, HandleCrash);

  // Crashes are expected to be in a TLV-style format of:
  // <name>:<length>:<value>
  // Length is encoded as a decimal number. It can be zero, but must consist of
  // at least one character
  // For file values, name actually contains both a description and a filename,
  // in a fixed format of: <description>"; filename="<filename>"
  bool ParseCrashLog(const std::string &data, const base::FilePath &dir,
                     const base::FilePath &minidump,
                     const std::string &basename);

  // Writes additional logs for |exe_name| to files based on |basename| within
  // |dir|. Crash report metadata key names and the corresponding file paths are
  // returned.
  std::map<std::string, base::FilePath> GetAdditionalLogs(
      const base::FilePath &dir,
      const std::string &basename,
      const std::string &exe_name);

  FILE *output_file_ptr_;

  // D-Bus proxy for debugd interface.  Unset in unit tests.
  std::unique_ptr<org::chromium::debugdProxy> debugd_proxy_;

  DISALLOW_COPY_AND_ASSIGN(ChromeCollector);
};

#endif  // CRASH_REPORTER_CHROME_COLLECTOR_H_

// Copyright (c) 2013 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/chrome_collector.h"

#include <pcrecpp.h>
#include <string>
#include <vector>

#include <base/file_util.h>
#include <base/logging.h>
#include <base/string_number_conversions.h>
#include <base/string_util.h>
#include "chromeos/process.h"
#include "chromeos/syslog_logging.h"

const char kDefaultMinidumpName[] = "upload_file_minidump";

namespace {

// Extract a string delimited by the given character, from the given offset
// into a source string. Returns false if the string is zero-sized or no
// delimiter was found.
bool GetDelimitedString(const std::string &str, char ch, size_t offset,
                        std::string *substr) {
  size_t at = str.find_first_of(ch, offset);
  if (at == std::string::npos || at == offset)
    return false;
  *substr = str.substr(offset, at - offset);
  return true;
}

} //namespace


ChromeCollector::ChromeCollector() {}

ChromeCollector::~ChromeCollector() {}

bool ChromeCollector::HandleCrash(const std::string &file_path,
                                  const std::string &pid_string,
                                  const std::string &uid_string,
                                  const std::string &exe_name) {
  if (!is_feedback_allowed_function_())
    return true;

  if (exe_name.find('/') != std::string::npos) {
    LOG(ERROR) << "exe_name contains illegal characters: " << exe_name;
    return false;
  }

  FilePath dir;
  uid_t uid = atoi(uid_string.c_str());
  pid_t pid = atoi(pid_string.c_str());
  if (!GetCreatedCrashDirectoryByEuid(uid, &dir, NULL)) {
    LOG(ERROR) << "Can't create crash directory for uid " << uid;
    return false;
  }

  std::string dump_basename = FormatDumpBasename(exe_name, time(NULL), pid);
  FilePath meta_path = GetCrashPath(dir, dump_basename, "meta");
  FilePath minidump_path = GetCrashPath(dir, dump_basename, "dmp");
  FilePath log_path = GetCrashPath(dir, dump_basename, "log");

  std::string data;
  if (!file_util::ReadFileToString(FilePath(file_path), &data)) {
    LOG(ERROR) << "Can't read crash log: " << file_path.c_str();
    return false;
  }

  if (!ParseCrashLog(data, dir, minidump_path, dump_basename)) {
    LOG(ERROR) << "Failed to parse Chrome's crash log";
    return false;
  }

  if (GetLogContents(FilePath(log_config_path_), exe_name, log_path))
    AddCrashMetaData("log", log_path.value());

  // We're done.
  WriteCrashMetaData(meta_path, exe_name, minidump_path.value());

  return true;
}

bool ChromeCollector::ParseCrashLog(const std::string &data,
                                    const FilePath &dir,
                                    const FilePath &minidump,
                                    const std::string &basename) {
  size_t at = 0;
  while (at < data.size()) {
    // Look for a : followed by a decimal number, followed by another :
    // followed by N bytes of data.
    std::string name, size_string;
    if (!GetDelimitedString(data, ':', at, &name)) {
      LOG(ERROR) << "Can't find : after name @ offset " << at;
      break;
    }
    at += name.size() + 1; // Skip the name & : delimiter.

    if (!GetDelimitedString(data, ':', at, &size_string)) {
      LOG(ERROR) << "Can't find : after size @ offset " << at;
      break;
    }
    at += size_string.size() + 1; // Skip the size & : delimiter.

    size_t size;
    if (!base::StringToSizeT(size_string, &size)) {
      LOG(ERROR) << "String not convertible to integer: " << size_string;
      break;
    }

    // Data would run past the end, did we get a truncated file?
    if (at + size > data.size()) {
      LOG(ERROR) << "Overrun, expected " << size << " bytes of data, got "
        << (data.size() - at);
      break;
    }

    if (name.find("filename") != std::string::npos) {
      // File.
      // Name will be in a semi-MIME format of
      // <descriptive name>"; filename="<name>"
      // Descriptive name will be upload_file_minidump for the dump.
      std::string desc, filename;
      pcrecpp::RE re("(.*)\" *; *filename=\"(.*)\"");
      if (!re.FullMatch(name.c_str(), &desc, &filename)) {
        LOG(ERROR) << "Filename was not in expected format: " << name;
        break;
      }

      if (desc.compare(kDefaultMinidumpName) == 0) {
        // The minidump.
        WriteNewFile(minidump, data.c_str() + at, size);
      } else {
        // Some other file.
        FilePath path = GetCrashPath(dir, basename + "-" + filename, "other");
        if (WriteNewFile(path, data.c_str() + at, size) >= 0) {
          AddCrashMetaUploadFile(desc, path.value());
        }
      }
    } else {
      // Other attribute.
      std::string value_str;
      value_str.reserve(size);

      // Since metadata is one line/value the values must be escaped properly.
      for (size_t i = at; i < at + size; i++) {
        switch (data[i]) {
          case '"':
          case '\\':
            value_str.push_back('\\');
            value_str.push_back(data[i]);
            break;

          case '\r':
            value_str += "\\r";
            break;

          case '\n':
            value_str += "\\n";
           break;

          case '\t':
            value_str += "\\t";
           break;

          case '\0':
            value_str += "\\0";
           break;

          default:
           value_str.push_back(data[i]);
           break;
        }
      }
      AddCrashMetaUploadData(name, value_str);
    }

    at += size;
  }

  return at == data.size();
}

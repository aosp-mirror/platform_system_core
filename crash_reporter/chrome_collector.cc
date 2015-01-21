// Copyright (c) 2013 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/chrome_collector.h"

#include <glib.h>
#include <pcrecpp.h>
#include <stdint.h>

#include <string>
#include <vector>

#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <chromeos/dbus/dbus.h>
#include <chromeos/dbus/service_constants.h>
#include <chromeos/process.h>
#include <chromeos/syslog_logging.h>

using base::FilePath;
using base::StringPrintf;

namespace {

const char kDefaultMinidumpName[] = "upload_file_minidump";

// Path to the gzip binary.
const char kGzipPath[] = "/bin/gzip";

// Filenames for logs attached to crash reports. Also used as metadata keys.
const char kChromeLogFilename[] = "chrome.txt";
const char kGpuStateFilename[] = "i915_error_state.log.xz";

// From //net/crash/collector/collector.h
const int kDefaultMaxUploadBytes = 1024 * 1024;

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

// Gets the GPU's error state from debugd and writes it to |error_state_path|.
// Returns true on success.
bool GetDriErrorState(const FilePath &error_state_path) {
  chromeos::dbus::BusConnection dbus = chromeos::dbus::GetSystemBusConnection();
  if (!dbus.HasConnection()) {
    LOG(ERROR) << "Error connecting to system D-Bus";
    return false;
  }

  chromeos::dbus::Proxy proxy(dbus,
                              debugd::kDebugdServiceName,
                              debugd::kDebugdServicePath,
                              debugd::kDebugdInterface);
  if (!proxy) {
    LOG(ERROR) << "Error creating D-Bus proxy to interface "
               << "'" << debugd::kDebugdServiceName << "'";
    return false;
  }

  chromeos::glib::ScopedError error;
  gchar *error_state = nullptr;
  if (!dbus_g_proxy_call(proxy.gproxy(), debugd::kGetLog,
                         &chromeos::Resetter(&error).lvalue(),
                         G_TYPE_STRING, "i915_error_state", G_TYPE_INVALID,
                         G_TYPE_STRING, &error_state, G_TYPE_INVALID)) {
    LOG(ERROR) << "Error performing D-Bus proxy call "
               << "'" << debugd::kGetLog << "'"
               << ": " << (error ? error->message : "");
    g_free(error_state);
    return false;
  }

  std::string error_state_str(error_state);
  g_free(error_state);

  if (error_state_str == "<empty>")
    return false;

  const char kBase64Header[] = "<base64>: ";
  const size_t kBase64HeaderLength = sizeof(kBase64Header) - 1;
  if (error_state_str.compare(0, kBase64HeaderLength, kBase64Header)) {
    LOG(ERROR) << "i915_error_state is missing base64 header";
    return false;
  }

  gsize len;
  guchar *decoded_error_state =
      g_base64_decode(error_state_str.c_str() + kBase64HeaderLength, &len);

  int written =
      base::WriteFile(error_state_path,
                      reinterpret_cast<const char *>(decoded_error_state), len);
  g_free(decoded_error_state);

  if (written < 0 || (gsize)written != len) {
    LOG(ERROR) << "Could not write file " << error_state_path.value();
    base::DeleteFile(error_state_path, false);
    return false;
  }

  return true;
}

// Gzip-compresses |path|, removes the original file, and returns the path of
// the new file. On failure, the original file is left alone and an empty path
// is returned.
FilePath GzipFile(const FilePath& path) {
  chromeos::ProcessImpl proc;
  proc.AddArg(kGzipPath);
  proc.AddArg(path.value());
  const int res = proc.Run();
  if (res != 0) {
    LOG(ERROR) << "Failed to gzip " << path.value();
    return FilePath();
  }
  return path.AddExtension(".gz");
}

}  // namespace


ChromeCollector::ChromeCollector() : output_file_ptr_(stdout) {}

ChromeCollector::~ChromeCollector() {}

bool ChromeCollector::HandleCrash(const FilePath &file_path,
                                  const std::string &pid_string,
                                  const std::string &uid_string,
                                  const std::string &exe_name) {
  if (!is_feedback_allowed_function_())
    return true;

  LOG(WARNING) << "Received crash notification for " << exe_name << "["
               << pid_string << "] user " << uid_string << " (called directly)";

  if (exe_name.find('/') != std::string::npos) {
    LOG(ERROR) << "exe_name contains illegal characters: " << exe_name;
    return false;
  }

  FilePath dir;
  uid_t uid = atoi(uid_string.c_str());
  pid_t pid = atoi(pid_string.c_str());
  if (!GetCreatedCrashDirectoryByEuid(uid, &dir, nullptr)) {
    LOG(ERROR) << "Can't create crash directory for uid " << uid;
    return false;
  }

  std::string dump_basename = FormatDumpBasename(exe_name, time(nullptr), pid);
  FilePath meta_path = GetCrashPath(dir, dump_basename, "meta");
  FilePath minidump_path = GetCrashPath(dir, dump_basename, "dmp");

  std::string data;
  if (!base::ReadFileToString(file_path, &data)) {
    LOG(ERROR) << "Can't read crash log: " << file_path.value();
    return false;
  }

  if (!ParseCrashLog(data, dir, minidump_path, dump_basename)) {
    LOG(ERROR) << "Failed to parse Chrome's crash log";
    return false;
  }


  int64_t report_size = 0;
  base::GetFileSize(minidump_path, &report_size);

  // Keyed by crash metadata key name.
  const std::map<std::string, base::FilePath> additional_logs =
      GetAdditionalLogs(dir, dump_basename, exe_name);
  for (auto it : additional_logs) {
    int64_t file_size = 0;
    if (!base::GetFileSize(it.second, &file_size)) {
      PLOG(WARNING) << "Unable to get size of " << it.second.value();
      continue;
    }
    if (report_size + file_size > kDefaultMaxUploadBytes) {
      LOG(INFO) << "Skipping upload of " << it.second.value() << "("
                << file_size << "B) because report size would exceed limit ("
                << kDefaultMaxUploadBytes << "B)";
      continue;
    }
    VLOG(1) << "Adding metadata: " << it.first << " -> " << it.second.value();
    // Call AddCrashMetaUploadFile() rather than AddCrashMetaData() here. The
    // former adds a prefix to the key name; without the prefix, only the key
    // "logs" appears to be displayed on the crash server.
    AddCrashMetaUploadFile(it.first, it.second.value());
    report_size += file_size;
  }

  // We're done.
  WriteCrashMetaData(meta_path, exe_name, minidump_path.value());

  fprintf(output_file_ptr_, "%s", kSuccessMagic);
  fflush(output_file_ptr_);

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
    at += name.size() + 1;  // Skip the name & : delimiter.

    if (!GetDelimitedString(data, ':', at, &size_string)) {
      LOG(ERROR) << "Can't find : after size @ offset " << at;
      break;
    }
    at += size_string.size() + 1;  // Skip the size & : delimiter.

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

std::map<std::string, base::FilePath> ChromeCollector::GetAdditionalLogs(
    const FilePath &dir,
    const std::string &basename,
    const std::string &exe_name) {
  std::map<std::string, base::FilePath> logs;

  // Run the command specified by the config file to gather logs.
  const FilePath chrome_log_path =
      GetCrashPath(dir, basename, kChromeLogFilename);
  if (GetLogContents(log_config_path_, exe_name, chrome_log_path)) {
    const FilePath compressed_path = GzipFile(chrome_log_path);
    if (!compressed_path.empty())
      logs[kChromeLogFilename] = compressed_path;
    else
      base::DeleteFile(chrome_log_path, false /* recursive */);
  }

  // Now get the GPU state from debugd.
  const FilePath dri_error_state_path =
      GetCrashPath(dir, basename, kGpuStateFilename);
  if (GetDriErrorState(dri_error_state_path))
    logs[kGpuStateFilename] = dri_error_state_path;

  return logs;
}

// static
const char ChromeCollector::kSuccessMagic[] = "_sys_cr_finished";

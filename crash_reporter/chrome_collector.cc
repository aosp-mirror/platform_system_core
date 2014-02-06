// Copyright (c) 2013 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/chrome_collector.h"

#include <fstream>
#include <glib.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <pcrecpp.h>
#include <string>
#include <vector>

#include <base/file_util.h>
#include <base/logging.h>
#include <base/rand_util.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include "chromeos/process.h"
#include "chromeos/syslog_logging.h"
#include "chromeos/dbus/dbus.h"
#include "chromeos/dbus/service_constants.h"

const char kDefaultMinidumpName[] = "upload_file_minidump";
const char kTarPath[] = "/bin/tar";
// From //net/crash/collector/collector.h
const int kDefaultMaxUploadBytes = 1024 * 1024;

const char kHeader[] = "kernel_task_states";
const char kEnter[] = "enter";
const char kLeave[] = "leave";
const char kSyslogPath[] = "/var/log/messages";
const char kFirstTwoColumnsRE[] = "\\S+\\s+\\S+\\s+";
const char kIdent[] = "crash_reporter";
const char kSpacesRE[] = "\\s+";
const char kKernelIdentRE[] = "kernel:";
const char kKernelTimestampRE[] = "\\[\\s*\\d+\\.\\d+\\]";
const char kTaskNameRE[] = "(.{15})";
// kernel's TASK_STATE_TO_CHAR_STR + '?'
const char kTaskStateRE[] = "([RSDTtZXxKW?])";
const char kHexNumRE[] = "([[:xdigit:]]+)";
const char kNumRE[] = "([[:digit:]]+)";
const char kRunning32[] = "running ";
const char kRunning64[] = " running task   ";
// This regex matches symbol+offset as printed by printk(%pB) or (%pS).
// See https://www.kernel.org/doc/Documentation/printk-formats.txt
// As noted in http://sourceware.org/binutils/docs-2.23.1/as/Symbol-Names.html
// symbols may contain periods and dollars, like "scm_recv.isra.18+0x61/0xdf".
// Strangely, occasionally there is an additional string following the symbol,
// like "qcusbnet_get+0x3e4/0x1e46 [gobi]".
// Those lines will be missing in the output, as parsing them is troublesome.
// Sometimes the address is printed and not the symbol. Those are ignored too.
const char kSymbolAndOffsetRE[] =
    "([[:alpha:]._$][[:alnum:]._$]*)\\+0x([[:xdigit:]]+)/0x([[:xdigit:]]+)";

using base::FilePath;
using base::StringPrintf;

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

bool GetDriErrorState(const chromeos::dbus::Proxy &proxy,
                      const FilePath &error_state_path) {
  chromeos::glib::ScopedError error;
  gchar *error_state = NULL;
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

  int written;
  written = file_util::WriteFile(error_state_path,
      reinterpret_cast<const char*>(decoded_error_state), len);
  g_free(decoded_error_state);

  if (written < 0 || (gsize)written != len) {
    LOG(ERROR) << "Could not write file " << error_state_path.value();
    base::DeleteFile(error_state_path, false);
    return false;
  }

  return true;
}

bool LogKernelTaskStates(const chromeos::dbus::Proxy &proxy,
                         const std::string &task_states_id) {
  // Wrap task states with unique id - header
  LOG(INFO) << kHeader << " " << task_states_id.c_str() << " " << kEnter;

  // Trigger asynchronous logging of task states
  chromeos::glib::ScopedError error;
  if (!dbus_g_proxy_call(proxy.gproxy(), debugd::kLogKernelTaskStates,
                         &chromeos::Resetter(&error).lvalue(),
                         G_TYPE_INVALID, G_TYPE_INVALID)) {
    LOG(ERROR) << "Error performing D-Bus proxy call "
               << "'" << debugd::kLogKernelTaskStates << "'"
               << ": " << (error ? error->message : "");
    return false;
  }

  // Give kernel a second to finish the asynchronous logging
  sleep(1);
  // Wrap task states with unique id - footer
  LOG(INFO) << kHeader << " " << task_states_id.c_str() << " " << kLeave;

  return true;
}

bool GetKernelTaskStates(const chromeos::dbus::Proxy &proxy,
                         std::vector<std::string> *output) {
  std::string task_states_id = StringPrintf("%016"PRIX64, base::RandUint64());

  if (!LogKernelTaskStates(proxy, task_states_id))
    return false;

  std::ifstream syslog_stream(kSyslogPath, std::ios::in);
  if (!syslog_stream.is_open()) {
    LOG(ERROR) << "Couldn't open syslog for reading";
    return false;
  }

  std::string ident_re = StringPrintf("%s\\[%d\\]:\\s+", kIdent, getpid());
  // 2013-07-05T11:52:55.530503-07:00 localhost crash_reporter[9349]:
  // kernel_task_states 33F114E753768B70 enter
  pcrecpp::RE enter_re(kFirstTwoColumnsRE + ident_re + kHeader + " " +
                       task_states_id + " " + kEnter);
  // 2013-07-05T11:52:56.556177-07:00 localhost crash_reporter[9349]:
  // kernel_task_states 33F114E753768B70 leave
  pcrecpp::RE leave_re(kFirstTwoColumnsRE + ident_re + kHeader + " " +
                       task_states_id + " " + kLeave);
  // 2013-06-21T21:18:14.855071+00:00 localhost kernel: [362142.027766]
  // NSS SSL ThreadW S 804f8e28     0  5995   1016 0x00000000
  pcrecpp::RE task_header_re(std::string(kFirstTwoColumnsRE) +
                             kKernelIdentRE + kSpacesRE +
                             kKernelTimestampRE + kSpacesRE +
                             kTaskNameRE + kSpacesRE +
                             kTaskStateRE + kSpacesRE +
                             kHexNumRE + kSpacesRE +
                             kNumRE + kSpacesRE +
                             kNumRE + kSpacesRE +
                             kNumRE + kSpacesRE +
                             "0x" + kHexNumRE);
  // 2013-06-21T21:18:14.815190+00:00 localhost kernel: [362142.016915]
  // rsyslogd        R running      0   340      1 0x00000000
  pcrecpp::RE task_header_run32_re(std::string(kFirstTwoColumnsRE) +
                                   kKernelIdentRE + kSpacesRE +
                                   kKernelTimestampRE + kSpacesRE +
                                   kTaskNameRE + kSpacesRE +
                                   kTaskStateRE + kSpacesRE +
                                   kRunning32 + kSpacesRE +
                                   kNumRE + kSpacesRE +
                                   kNumRE + kSpacesRE +
                                   kNumRE + kSpacesRE +
                                   "0x" + kHexNumRE);
  // 2013-06-21T14:11:18.718810-07:00 localhost kernel: [  656.217932]
  // kworker/2:1     R  running task        0    54      2 0x00000000
  pcrecpp::RE task_header_run64_re(std::string(kFirstTwoColumnsRE) +
                                   kKernelIdentRE + kSpacesRE +
                                   kKernelTimestampRE + kSpacesRE +
                                   kTaskNameRE + kSpacesRE +
                                   kTaskStateRE + kSpacesRE +
                                   kRunning64 + kSpacesRE +
                                   kNumRE + kSpacesRE +
                                   kNumRE + kSpacesRE +
                                   kNumRE + kSpacesRE +
                                   "0x" + kHexNumRE);
  std::string address_re = std::string("\\[<") + kHexNumRE + ">\\]";
  std::string braced_sym_re = std::string("\\(") + kSymbolAndOffsetRE + "\\)";
  // 2013-07-05T11:53:20.141355-07:00 localhost kernel: [  169.476749]
  // [<8002fb74>] (do_wait+0x1a8/0x248) from [<80030c48>] (sys_wait4+0xbc/0xf8)
  pcrecpp::RE arm_stack_re(std::string(kFirstTwoColumnsRE) +
                           kKernelIdentRE + kSpacesRE +
                           kKernelTimestampRE + kSpacesRE +
                           address_re + kSpacesRE +
                           braced_sym_re + kSpacesRE +
                           "from" + kSpacesRE +
                           address_re + kSpacesRE +
                           braced_sym_re);
  // 2013-06-21T14:12:34.457315-07:00 localhost kernel: [  731.965907]
  // [<ffffffff814aa602>] ? system_call_fastpath+0x16/0x1b
  pcrecpp::RE x86_stack_re(std::string(kFirstTwoColumnsRE) +
                           kKernelIdentRE + kSpacesRE +
                           kKernelTimestampRE + kSpacesRE +
                           address_re + kSpacesRE +
                           "(\\?\\s+)?" +
                           kSymbolAndOffsetRE);

  bool enter_matched = false;
  bool leave_matched = false;
  uint64 prev_address = 0;
  std::string line;
  while (std::getline(syslog_stream, line)) {
    if (leave_re.FullMatch(line)) {
      if (!enter_matched) {
        LOG(ERROR) << "Task states header not found before footer";
        return false;
      }
      leave_matched = true;
      break;  // Stop processing input after footer
    }

    if (enter_re.FullMatch(line)) {
      if (enter_matched) {
        LOG(ERROR) << "Task states header encountered twice";
        return false;
      }
      enter_matched = true;
      continue;
    }

    if(!enter_matched)
      continue;  // Skip lines before header

    std::string task_name, task_state;
    uint64 address1, address2;
    unsigned long free_stack;
    pid_t pid, ppid;
    unsigned long flags;
    std::string sym1, sym2;
    uint64 offset1a, offset1b, offset2a, offset2b;
    std::string question;

    if (task_header_re.FullMatch(line, &task_name, &task_state,
                                 pcrecpp::Hex(&address1), &free_stack, &pid,
                                 &ppid, pcrecpp::Hex(&flags))) {
      prev_address = 0;
      output->push_back(StringPrintf("%s %s %016"PRIx64" %5lu %5d %6d 0x%08lx",
                                     task_name.c_str(), task_state.c_str(),
                                     address1, free_stack, pid, ppid, flags));
    } else if (task_header_run32_re.FullMatch(line, &task_name, &task_state,
                                              &free_stack, &pid, &ppid,
                                              pcrecpp::Hex(&flags)) ||
        task_header_run64_re.FullMatch(line, &task_name, &task_state,
                                       &free_stack, &pid, &ppid,
                                       pcrecpp::Hex(&flags))) {
      prev_address = 0;
      output->push_back(StringPrintf("%s %s %s %5lu %5d %6d 0x%08lx",
                                     task_name.c_str(), task_state.c_str(),
                                     kRunning64, free_stack, pid, ppid, flags));
    } else if (arm_stack_re.FullMatch(line, pcrecpp::Hex(&address1), &sym1,
                                      pcrecpp::Hex(&offset1a),
                                      pcrecpp::Hex(&offset1b),
                                      pcrecpp::Hex(&address2), &sym2,
                                      pcrecpp::Hex(&offset2a),
                                      pcrecpp::Hex(&offset2b))) {
      if (prev_address != address1) {
        output->push_back(StringPrintf("%s+0x%"PRIx64"/0x%"PRIx64,
                                       sym1.c_str(), offset1a, offset1b));
      }
      output->push_back(StringPrintf("%s+0x%"PRIx64"/0x%"PRIx64,
                                     sym2.c_str(), offset2a, offset2b));
      prev_address = address2;
    } else if (x86_stack_re.FullMatch(line, pcrecpp::Hex(&address1), &question,
                                      &sym1, pcrecpp::Hex(&offset1a),
                                      pcrecpp::Hex(&offset1b))) {
      output->push_back(StringPrintf("%s%s+0x%"PRIx64"/0x%"PRIx64,
                                     question.c_str(), sym1.c_str(),
                                     offset1a, offset1b));
    }
  }
  syslog_stream.close();

  if(!enter_matched || !leave_matched) {
    LOG(ERROR) << "Task states header or footer not found";
    return false;
  }

  return true;
}

bool WriteKernelTaskStates(const chromeos::dbus::Proxy &proxy,
                           const FilePath &task_states_path) {
  std::ofstream task_states_stream(task_states_path.value().c_str(),
                                   std::ios::out);
  if (!task_states_stream.is_open()) {
    LOG(ERROR) << "Could not write file " << task_states_path.value();
    return false;
  }

  std::vector<std::string> task_sates;
  if (!GetKernelTaskStates(proxy, &task_sates)) {
    base::DeleteFile(task_states_path, false);
    return false;
  }

  for (std::vector<std::string>::iterator it = task_sates.begin();
      it != task_sates.end(); ++it) {
    task_states_stream << *it << std::endl;
  }
  task_states_stream.close();

  return true;
}

bool GetAdditionalLogs(const FilePath &log_path) {
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

  FilePath error_state_path =
      log_path.DirName().Append("i915_error_state.log.xz");
  bool has_dri_error_state = false;
  if (GetDriErrorState(proxy, error_state_path))
    has_dri_error_state = true;

  FilePath task_states_path = log_path.DirName().Append("task_states.log");
  bool has_task_states = false;
  if (WriteKernelTaskStates(proxy, task_states_path)) {
    has_task_states = true;
  }

  if (!has_dri_error_state && !has_task_states)
    return false;

  chromeos::ProcessImpl tar_process;
  tar_process.AddArg(kTarPath);
  tar_process.AddArg("cfJ");
  tar_process.AddArg(log_path.value());
  tar_process.AddStringOption("-C", log_path.DirName().value());
  if (has_dri_error_state)
    tar_process.AddArg(error_state_path.BaseName().value());
  if (has_task_states)
    tar_process.AddArg(task_states_path.BaseName().value());
  int res = tar_process.Run();

  base::DeleteFile(error_state_path, false);
  base::DeleteFile(task_states_path, false);

  if (res || !base::PathExists(log_path)) {
    LOG(ERROR) << "Could not tar file " << log_path.value();
    return false;
  }

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
  FilePath log_path = GetCrashPath(dir, dump_basename, "log.tar.xz");

  std::string data;
  if (!base::ReadFileToString(FilePath(file_path), &data)) {
    LOG(ERROR) << "Can't read crash log: " << file_path.c_str();
    return false;
  }

  if (!ParseCrashLog(data, dir, minidump_path, dump_basename)) {
    LOG(ERROR) << "Failed to parse Chrome's crash log";
    return false;
  }

  if (GetAdditionalLogs(log_path)) {
    int64 minidump_size = 0;
    int64 log_size = 0;
    if (base::GetFileSize(minidump_path, &minidump_size) &&
        base::GetFileSize(log_path, &log_size) &&
        minidump_size > 0 && log_size > 0 &&
        minidump_size + log_size < kDefaultMaxUploadBytes) {
      AddCrashMetaData("log", log_path.value());
    } else {
      LOG(INFO) << "Skipping logs upload to prevent discarding minidump "
          "because of report size limit < " << minidump_size + log_size;
      base::DeleteFile(log_path, false);
    }
  }

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

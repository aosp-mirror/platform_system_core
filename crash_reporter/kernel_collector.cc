// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/kernel_collector.h"

#include "base/file_util.h"
#include "base/logging.h"
#include "base/string_util.h"

const char KernelCollector::kClearingSequence[] = " ";
static const char kDefaultKernelStackSignature[] =
    "kernel-UnspecifiedStackSignature";
static const char kKernelExecName[] = "kernel";
const pid_t kKernelPid = 0;
static const char kKernelSignatureKey[] = "sig";
// Byte length of maximum human readable portion of a kernel crash signature.
static const int kMaxHumanStringLength = 40;
static const char kPreservedDumpPath[] = "/sys/kernel/debug/preserved/kcrash";
const uid_t kRootUid = 0;
// Time in seconds from the final kernel log message for a call stack
// to count towards the signature of the kcrash.
static const int kSignatureTimestampWindow = 2;
// Kernel log timestamp regular expression.
static const std::string kTimestampRegex("^<.*>\\[\\s*(\\d+\\.\\d+)\\]");

KernelCollector::KernelCollector()
    : is_enabled_(false),
      preserved_dump_path_(kPreservedDumpPath) {
}

KernelCollector::~KernelCollector() {
}

void KernelCollector::OverridePreservedDumpPath(const FilePath &file_path) {
  preserved_dump_path_ = file_path;
}

bool KernelCollector::LoadPreservedDump(std::string *contents) {
  // clear contents since ReadFileToString actually appends to the string.
  contents->clear();
  if (!file_util::ReadFileToString(preserved_dump_path_, contents)) {
    LOG(ERROR) << "Unable to read " << preserved_dump_path_.value();
    return false;
  }
  return true;
}

bool KernelCollector::Enable() {
  if (!file_util::PathExists(preserved_dump_path_)) {
    LOG(WARNING) << "Kernel does not support crash dumping";
    return false;
  }

  // To enable crashes, we will eventually need to set
  // the chnv bit in BIOS, but it does not yet work.
  LOG(INFO) << "Enabling kernel crash handling";
  is_enabled_ = true;
  return true;
}

bool KernelCollector::ClearPreservedDump() {
  // It is necessary to write at least one byte to the kcrash file for
  // the log to actually be cleared.
  if (file_util::WriteFile(
          preserved_dump_path_,
          kClearingSequence,
          strlen(kClearingSequence)) != strlen(kClearingSequence)) {
    LOG(ERROR) << "Failed to clear kernel crash dump";
    return false;
  }
  LOG(INFO) << "Cleared kernel crash diagnostics";
  return true;
}

// Hash a string to a number.  We define our own hash function to not
// be dependent on a C++ library that might change.  This function
// uses basically the same approach as tr1/functional_hash.h but with
// a larger prime number (16127 vs 131).
static unsigned HashString(const std::string &input) {
  unsigned hash = 0;
  for (size_t i = 0; i < input.length(); ++i)
    hash = hash * 16127 + input[i];
  return hash;
}

void KernelCollector::ProcessStackTrace(
    pcrecpp::StringPiece kernel_dump,
    bool print_diagnostics,
    unsigned *hash,
    float *last_stack_timestamp) {
  pcrecpp::RE line_re("(.+)", pcrecpp::MULTILINE());
  pcrecpp::RE stack_trace_start_re(kTimestampRegex + " Call Trace:$");
  // Match lines such as the following and grab out "error_code".
  // <4>[ 6066.849504]  [<7937bcee>] error_code+0x66/0x6c
  pcrecpp::RE stack_entry_re(kTimestampRegex +
                             "  \\[<.*>\\]([\\s\\?]+)([^\\+ ]+)");
  std::string line;
  std::string hashable;

  *hash = 0;
  *last_stack_timestamp = 0;

  while (line_re.FindAndConsume(&kernel_dump, &line)) {
    std::string certainty;
    std::string function_name;
    if (stack_trace_start_re.PartialMatch(line, last_stack_timestamp)) {
      if (print_diagnostics) {
        printf("Stack trace starting. Clearing any prior traces.\n");
      }
      hashable.clear();
    } else if (stack_entry_re.PartialMatch(line,
                                           last_stack_timestamp,
                                           &certainty,
                                           &function_name)) {
      bool is_certain = certainty.find('?') == std::string::npos;
      if (print_diagnostics) {
        printf("@%f: stack entry for %s (%s)\n",
               *last_stack_timestamp,
               function_name.c_str(),
               is_certain ? "certain" : "uncertain");
      }
      // Do not include any uncertain (prefixed by '?') frames in our hash.
      if (!is_certain)
        continue;
      if (!hashable.empty())
        hashable.append("|");
      hashable.append(function_name);
    }
  }

  *hash = HashString(hashable);

  if (print_diagnostics) {
    printf("Hash based on stack trace: \"%s\" at %f.\n",
           hashable.c_str(), *last_stack_timestamp);
  }
}

bool KernelCollector::FindCrashingFunction(
    pcrecpp::StringPiece kernel_dump,
    bool print_diagnostics,
    float stack_trace_timestamp,
    std::string *crashing_function) {
  pcrecpp::RE eip_re(kTimestampRegex + " EIP: \\[<.*>\\] ([^\\+ ]+).*",
                     pcrecpp::MULTILINE());
  float timestamp = 0;
  while (eip_re.FindAndConsume(&kernel_dump, &timestamp, crashing_function)) {
    if (print_diagnostics) {
      printf("@%f: found crashing function %s\n",
             timestamp,
             crashing_function->c_str());
    }
  }
  if (timestamp == 0) {
    if (print_diagnostics) {
      printf("Found no crashing function.\n");
    }
    return false;
  }
  if (stack_trace_timestamp != 0 &&
      abs(stack_trace_timestamp - timestamp) > kSignatureTimestampWindow) {
    if (print_diagnostics) {
      printf("Found crashing function but not within window.\n");
    }
    return false;
  }
  if (print_diagnostics) {
    printf("Found crashing function %s\n", crashing_function->c_str());
  }
  return true;
}

bool KernelCollector::FindPanicMessage(pcrecpp::StringPiece kernel_dump,
                                       bool print_diagnostics,
                                       std::string *panic_message) {
  // Match lines such as the following and grab out "Fatal exception"
  // <0>[  342.841135] Kernel panic - not syncing: Fatal exception
  pcrecpp::RE kernel_panic_re(kTimestampRegex +
                              " Kernel panic[^\\:]*\\:\\s*(.*)",
                              pcrecpp::MULTILINE());
  float timestamp = 0;
  while (kernel_panic_re.FindAndConsume(&kernel_dump,
                                        &timestamp,
                                        panic_message)) {
    if (print_diagnostics) {
      printf("@%f: panic message %s\n",
             timestamp,
             panic_message->c_str());
    }
  }
  if (timestamp == 0) {
    if (print_diagnostics) {
      printf("Found no panic message.\n");
    }
    return false;
  }
  return true;
}

bool KernelCollector::ComputeKernelStackSignature(
    const std::string &kernel_dump,
    std::string *kernel_signature,
    bool print_diagnostics) {
  unsigned stack_hash = 0;
  float last_stack_timestamp = 0;
  std::string human_string;

  ProcessStackTrace(kernel_dump,
                    print_diagnostics,
                    &stack_hash,
                    &last_stack_timestamp);

  if (!FindCrashingFunction(kernel_dump,
                            print_diagnostics,
                            last_stack_timestamp,
                            &human_string)) {
    if (!FindPanicMessage(kernel_dump, print_diagnostics, &human_string)) {
      if (print_diagnostics) {
        printf("Found no human readable string, using empty string.\n");
      }
      human_string.clear();
    }
  }

  if (human_string.empty() && stack_hash == 0) {
    if (print_diagnostics) {
      printf("Found neither a stack nor a human readable string, failing.\n");
    }
    return false;
  }

  human_string = human_string.substr(0, kMaxHumanStringLength);
  *kernel_signature = StringPrintf("%s-%s-%08X",
                                   kKernelExecName,
                                   human_string.c_str(),
                                   stack_hash);
  return true;
}

bool KernelCollector::Collect() {
  std::string kernel_dump;
  FilePath root_crash_directory;
  if (!LoadPreservedDump(&kernel_dump)) {
    return false;
  }
  if (kernel_dump.empty()) {
    return false;
  }
  std::string signature;
  if (!ComputeKernelStackSignature(kernel_dump, &signature, false)) {
    signature = kDefaultKernelStackSignature;
  }

  bool feedback = is_feedback_allowed_function_();

  LOG(INFO) << "Received prior crash notification from "
            << "kernel (signature " << signature << ") ("
            << (feedback ? "handling" : "ignoring - no consent") << ")";

  if (feedback) {
    count_crash_function_();

    if (!GetCreatedCrashDirectoryByEuid(kRootUid,
                                        &root_crash_directory,
                                        NULL)) {
      return true;
    }

    std::string dump_basename =
        FormatDumpBasename(kKernelExecName,
                           time(NULL),
                           kKernelPid);
    FilePath kernel_crash_path = root_crash_directory.Append(
        StringPrintf("%s.kcrash", dump_basename.c_str()));

    // We must use WriteNewFile instead of file_util::WriteFile as we
    // do not want to write with root access to a symlink that an attacker
    // might have created.
    if (WriteNewFile(kernel_crash_path,
                     kernel_dump.data(),
                     kernel_dump.length()) !=
        static_cast<int>(kernel_dump.length())) {
      LOG(INFO) << "Failed to write kernel dump to "
                << kernel_crash_path.value().c_str();
      return true;
    }

    AddCrashMetaData(kKernelSignatureKey, signature);
    WriteCrashMetaData(
        root_crash_directory.Append(
            StringPrintf("%s.meta", dump_basename.c_str())),
        kKernelExecName,
        kernel_crash_path.value());

    LOG(INFO) << "Stored kcrash to " << kernel_crash_path.value();
  }
  if (!ClearPreservedDump()) {
    return false;
  }

  return true;
}

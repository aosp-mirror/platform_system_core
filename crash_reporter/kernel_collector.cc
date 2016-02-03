/*
 * Copyright (C) 2012 The Android Open Source Project
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

#include "kernel_collector.h"

#include <map>
#include <sys/stat.h>

#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>

using base::FilePath;
using base::StringPrintf;

namespace {

const char kDefaultKernelStackSignature[] = "kernel-UnspecifiedStackSignature";
const char kDumpParentPath[] = "/sys/fs";
const char kDumpPath[] = "/sys/fs/pstore";
const char kDumpFormat[] = "dmesg-ramoops-%zu";
const char kKernelExecName[] = "kernel";
// Maximum number of records to examine in the kDumpPath.
const size_t kMaxDumpRecords = 100;
const pid_t kKernelPid = 0;
const char kKernelSignatureKey[] = "sig";
// Byte length of maximum human readable portion of a kernel crash signature.
const int kMaxHumanStringLength = 40;
const uid_t kRootUid = 0;
// Time in seconds from the final kernel log message for a call stack
// to count towards the signature of the kcrash.
const int kSignatureTimestampWindow = 2;
// Kernel log timestamp regular expression.
const char kTimestampRegex[] = "^<.*>\\[\\s*(\\d+\\.\\d+)\\]";

//
// These regular expressions enable to us capture the PC in a backtrace.
// The backtrace is obtained through dmesg or the kernel's preserved/kcrashmem
// feature.
//
// For ARM we see:
//   "<5>[   39.458982] PC is at write_breakme+0xd0/0x1b4"
// For MIPS we see:
//   "<5>[ 3378.552000] epc   : 804010f0 lkdtm_do_action+0x68/0x3f8"
// For x86:
//   "<0>[   37.474699] EIP: [<790ed488>] write_breakme+0x80/0x108
//    SS:ESP 0068:e9dd3efc"
//
const char* const kPCRegex[] = {
  0,
  " PC is at ([^\\+ ]+).*",
  " epc\\s+:\\s+\\S+\\s+([^\\+ ]+).*",  // MIPS has an exception program counter
  " EIP: \\[<.*>\\] ([^\\+ ]+).*",  // X86 uses EIP for the program counter
  " RIP  \\[<.*>\\] ([^\\+ ]+).*",  // X86_64 uses RIP for the program counter
};

static_assert(arraysize(kPCRegex) == KernelCollector::kArchCount,
              "Missing Arch PC regexp");

}  // namespace

KernelCollector::KernelCollector()
    : is_enabled_(false),
      ramoops_dump_path_(kDumpPath),
      records_(0),
      // We expect crash dumps in the format of architecture we are built for.
      arch_(GetCompilerArch()) {
}

KernelCollector::~KernelCollector() {
}

void KernelCollector::OverridePreservedDumpPath(const FilePath &file_path) {
  ramoops_dump_path_ = file_path;
}

bool KernelCollector::ReadRecordToString(std::string *contents,
                                         size_t current_record,
                                         bool *record_found) {
  // A record is a ramoops dump. It has an associated size of "record_size".
  std::string record;
  std::string captured;

  // Ramoops appends a header to a crash which contains ==== followed by a
  // timestamp. Ignore the header.
  pcrecpp::RE record_re(
      "====\\d+\\.\\d+\n(.*)",
      pcrecpp::RE_Options().set_multiline(true).set_dotall(true));

  pcrecpp::RE sanity_check_re("\n<\\d+>\\[\\s*(\\d+\\.\\d+)\\]");

  FilePath ramoops_record;
  GetRamoopsRecordPath(&ramoops_record, current_record);
  if (!base::ReadFileToString(ramoops_record, &record)) {
    LOG(ERROR) << "Unable to open " << ramoops_record.value();
    return false;
  }

  *record_found = false;
  if (record_re.FullMatch(record, &captured)) {
    // Found a ramoops header, so strip the header and append the rest.
    contents->append(captured);
    *record_found = true;
  } else if (sanity_check_re.PartialMatch(record.substr(0, 1024))) {
    // pstore compression has been added since kernel 3.12. In order to
    // decompress dmesg correctly, ramoops driver has to strip the header
    // before handing over the record to the pstore driver, so we don't
    // need to do it here anymore. However, the sanity check is needed because
    // sometimes a pstore record is just a chunk of uninitialized memory which
    // is not the result of a kernel crash. See crbug.com/443764
    contents->append(record);
    *record_found = true;
  } else {
    LOG(WARNING) << "Found invalid record at " << ramoops_record.value();
  }

  // Remove the record from pstore after it's found.
  if (*record_found)
    base::DeleteFile(ramoops_record, false);

  return true;
}

void KernelCollector::GetRamoopsRecordPath(FilePath *path,
                                           size_t record) {
  // Disable error "format not a string literal, argument types not checked"
  // because this is valid, but GNU apparently doesn't bother checking a const
  // format string.
  #pragma GCC diagnostic push
  #pragma GCC diagnostic ignored "-Wformat-nonliteral"
  *path = ramoops_dump_path_.Append(StringPrintf(kDumpFormat, record));
  #pragma GCC diagnostic pop
}

bool KernelCollector::LoadParameters() {
  // Discover how many ramoops records are being exported by the driver.
  size_t count;

  for (count = 0; count < kMaxDumpRecords; ++count) {
    FilePath ramoops_record;
    GetRamoopsRecordPath(&ramoops_record, count);

    if (!base::PathExists(ramoops_record))
      break;
  }

  records_ = count;
  return (records_ > 0);
}

bool KernelCollector::LoadPreservedDump(std::string *contents) {
  // Load dumps from the preserved memory and save them in contents.
  // Since the system is set to restart on oops we won't actually ever have
  // multiple records (only 0 or 1), but check in case we don't restart on
  // oops in the future.
  bool any_records_found = false;
  bool record_found = false;
  // clear contents since ReadFileToString actually appends to the string.
  contents->clear();

  for (size_t i = 0; i < records_; ++i) {
    if (!ReadRecordToString(contents, i, &record_found)) {
      break;
    }
    if (record_found) {
      any_records_found = true;
    }
  }

  if (!any_records_found) {
    LOG(ERROR) << "No valid records found in " << ramoops_dump_path_.value();
    return false;
  }

  return true;
}

void KernelCollector::StripSensitiveData(std::string *kernel_dump) {
  // Strip any data that the user might not want sent up to the crash servers.
  // We'll read in from kernel_dump and also place our output there.
  //
  // At the moment, the only sensitive data we strip is MAC addresses.

  // Get rid of things that look like MAC addresses, since they could possibly
  // give information about where someone has been.  This is strings that look
  // like this: 11:22:33:44:55:66
  // Complications:
  // - Within a given kernel_dump, want to be able to tell when the same MAC
  //   was used more than once.  Thus, we'll consistently replace the first
  //   MAC found with 00:00:00:00:00:01, the second with ...:02, etc.
  // - ACPI commands look like MAC addresses.  We'll specifically avoid getting
  //   rid of those.
  std::ostringstream result;
  std::string pre_mac_str;
  std::string mac_str;
  std::map<std::string, std::string> mac_map;
  pcrecpp::StringPiece input(*kernel_dump);

  // This RE will find the next MAC address and can return us the data preceding
  // the MAC and the MAC itself.
  pcrecpp::RE mac_re("(.*?)("
                     "[0-9a-fA-F][0-9a-fA-F]:"
                     "[0-9a-fA-F][0-9a-fA-F]:"
                     "[0-9a-fA-F][0-9a-fA-F]:"
                     "[0-9a-fA-F][0-9a-fA-F]:"
                     "[0-9a-fA-F][0-9a-fA-F]:"
                     "[0-9a-fA-F][0-9a-fA-F])",
                     pcrecpp::RE_Options()
                       .set_multiline(true)
                       .set_dotall(true));

  // This RE will identify when the 'pre_mac_str' shows that the MAC address
  // was really an ACPI cmd.  The full string looks like this:
  //   ata1.00: ACPI cmd ef/10:03:00:00:00:a0 (SET FEATURES) filtered out
  pcrecpp::RE acpi_re("ACPI cmd ef/$",
                      pcrecpp::RE_Options()
                        .set_multiline(true)
                        .set_dotall(true));

  // Keep consuming, building up a result string as we go.
  while (mac_re.Consume(&input, &pre_mac_str, &mac_str)) {
    if (acpi_re.PartialMatch(pre_mac_str)) {
      // We really saw an ACPI command; add to result w/ no stripping.
      result << pre_mac_str << mac_str;
    } else {
      // Found a MAC address; look up in our hash for the mapping.
      std::string replacement_mac = mac_map[mac_str];
      if (replacement_mac == "") {
        // It wasn't present, so build up a replacement string.
        int mac_id = mac_map.size();

        // Handle up to 2^32 unique MAC address; overkill, but doesn't hurt.
        replacement_mac = StringPrintf("00:00:%02x:%02x:%02x:%02x",
                                       (mac_id & 0xff000000) >> 24,
                                       (mac_id & 0x00ff0000) >> 16,
                                       (mac_id & 0x0000ff00) >> 8,
                                       (mac_id & 0x000000ff));
        mac_map[mac_str] = replacement_mac;
      }

      // Dump the string before the MAC and the fake MAC address into result.
      result << pre_mac_str << replacement_mac;
    }
  }

  // One last bit of data might still be in the input.
  result << input;

  // We'll just assign right back to kernel_dump.
  *kernel_dump = result.str();
}

bool KernelCollector::DumpDirMounted() {
  struct stat st_parent;
  if (stat(kDumpParentPath, &st_parent)) {
    PLOG(WARNING) << "Could not stat " << kDumpParentPath;
    return false;
  }

  struct stat st_dump;
  if (stat(kDumpPath, &st_dump)) {
    PLOG(WARNING) << "Could not stat " << kDumpPath;
    return false;
  }

  if (st_parent.st_dev == st_dump.st_dev) {
    LOG(WARNING) << "Dump dir " << kDumpPath << " not mounted";
    return false;
  }

  return true;
}

bool KernelCollector::Enable() {
  if (arch_ == kArchUnknown || arch_ >= kArchCount ||
      kPCRegex[arch_] == nullptr) {
    LOG(WARNING) << "KernelCollector does not understand this architecture";
    return false;
  }

  if (!DumpDirMounted()) {
    LOG(WARNING) << "Kernel does not support crash dumping";
    return false;
  }

  // To enable crashes, we will eventually need to set
  // the chnv bit in BIOS, but it does not yet work.
  LOG(INFO) << "Enabling kernel crash handling";
  is_enabled_ = true;
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
    float *last_stack_timestamp,
    bool *is_watchdog_crash) {
  pcrecpp::RE line_re("(.+)", pcrecpp::MULTILINE());
  pcrecpp::RE stack_trace_start_re(std::string(kTimestampRegex) +
        " (Call Trace|Backtrace):$");

  // Match lines such as the following and grab out "function_name".
  // The ? may or may not be present.
  //
  // For ARM:
  // <4>[ 3498.731164] [<c0057220>] ? (function_name+0x20/0x2c) from
  // [<c018062c>] (foo_bar+0xdc/0x1bc)
  //
  // For MIPS:
  // <5>[ 3378.656000] [<804010f0>] lkdtm_do_action+0x68/0x3f8
  //
  // For X86:
  // <4>[ 6066.849504]  [<7937bcee>] ? function_name+0x66/0x6c
  //
  pcrecpp::RE stack_entry_re(std::string(kTimestampRegex) +
    "\\s+\\[<[[:xdigit:]]+>\\]"      // Matches "  [<7937bcee>]"
    "([\\s\\?(]+)"                   // Matches " ? (" (ARM) or " ? " (X86)
    "([^\\+ )]+)");                  // Matches until delimiter reached
  std::string line;
  std::string hashable;
  std::string previous_hashable;
  bool is_watchdog = false;

  *hash = 0;
  *last_stack_timestamp = 0;

  // Find the last and second-to-last stack traces.  The latter is used when
  // the panic is from a watchdog timeout.
  while (line_re.FindAndConsume(&kernel_dump, &line)) {
    std::string certainty;
    std::string function_name;
    if (stack_trace_start_re.PartialMatch(line, last_stack_timestamp)) {
      if (print_diagnostics) {
        printf("Stack trace starting.%s\n",
               hashable.empty() ? "" : "  Saving prior trace.");
      }
      previous_hashable = hashable;
      hashable.clear();
      is_watchdog = false;
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
      if (function_name == "watchdog_timer_fn" ||
          function_name == "watchdog") {
        is_watchdog = true;
      }
      hashable.append(function_name);
    }
  }

  // If the last stack trace contains a watchdog function we assume the panic
  // is from the watchdog timer, and we hash the previous stack trace rather
  // than the last one, assuming that the previous stack is that of the hung
  // thread.
  //
  // In addition, if the hashable is empty (meaning all frames are uncertain,
  // for whatever reason) also use the previous frame, as it cannot be any
  // worse.
  if (is_watchdog || hashable.empty()) {
    hashable = previous_hashable;
  }

  *hash = HashString(hashable);
  *is_watchdog_crash = is_watchdog;

  if (print_diagnostics) {
    printf("Hash based on stack trace: \"%s\" at %f.\n",
           hashable.c_str(), *last_stack_timestamp);
  }
}

// static
KernelCollector::ArchKind KernelCollector::GetCompilerArch() {
#if defined(COMPILER_GCC) && defined(ARCH_CPU_ARM_FAMILY)
  return kArchArm;
#elif defined(COMPILER_GCC) && defined(ARCH_CPU_MIPS_FAMILY)
  return kArchMips;
#elif defined(COMPILER_GCC) && defined(ARCH_CPU_X86_64)
  return kArchX86_64;
#elif defined(COMPILER_GCC) && defined(ARCH_CPU_X86_FAMILY)
  return kArchX86;
#else
  return kArchUnknown;
#endif
}

bool KernelCollector::FindCrashingFunction(
  pcrecpp::StringPiece kernel_dump,
  bool print_diagnostics,
  float stack_trace_timestamp,
  std::string *crashing_function) {
  float timestamp = 0;

  // Use the correct regex for this architecture.
  pcrecpp::RE eip_re(std::string(kTimestampRegex) + kPCRegex[arch_],
                     pcrecpp::MULTILINE());

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
      abs(static_cast<int>(stack_trace_timestamp - timestamp))
        > kSignatureTimestampWindow) {
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
  pcrecpp::RE kernel_panic_re(std::string(kTimestampRegex) +
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
  bool is_watchdog_crash;

  ProcessStackTrace(kernel_dump,
                    print_diagnostics,
                    &stack_hash,
                    &last_stack_timestamp,
                    &is_watchdog_crash);

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
  *kernel_signature = StringPrintf("%s-%s%s-%08X",
                                   kKernelExecName,
                                   (is_watchdog_crash ? "(HANG)-" : ""),
                                   human_string.c_str(),
                                   stack_hash);
  return true;
}

bool KernelCollector::Collect() {
  std::string kernel_dump;
  FilePath root_crash_directory;

  if (!LoadParameters()) {
    return false;
  }
  if (!LoadPreservedDump(&kernel_dump)) {
    return false;
  }
  StripSensitiveData(&kernel_dump);
  if (kernel_dump.empty()) {
    return false;
  }
  std::string signature;
  if (!ComputeKernelStackSignature(kernel_dump, &signature, false)) {
    signature = kDefaultKernelStackSignature;
  }

  std::string reason = "handling";
  bool feedback = true;
  if (IsDeveloperImage()) {
    reason = "developer build - always dumping";
    feedback = true;
  } else if (!is_feedback_allowed_function_()) {
    reason = "ignoring - no consent";
    feedback = false;
  }

  LOG(INFO) << "Received prior crash notification from "
            << "kernel (signature " << signature << ") (" << reason << ")";

  if (feedback) {
    count_crash_function_();

    if (!GetCreatedCrashDirectoryByEuid(kRootUid,
                                        &root_crash_directory,
                                        nullptr)) {
      return true;
    }

    std::string dump_basename =
        FormatDumpBasename(kKernelExecName, time(nullptr), kKernelPid);
    FilePath kernel_crash_path = root_crash_directory.Append(
        StringPrintf("%s.kcrash", dump_basename.c_str()));

    // We must use WriteNewFile instead of base::WriteFile as we
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

  return true;
}

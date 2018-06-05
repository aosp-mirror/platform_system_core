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

// The bootstat command provides options to persist boot events with the current
// timestamp, dump the persisted events, and log all events to EventLog to be
// uploaded to Android log storage via Tron.

#include <getopt.h>
#include <sys/klog.h>
#include <unistd.h>

#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdio>
#include <ctime>
#include <map>
#include <memory>
#include <regex>
#include <string>
#include <utility>
#include <vector>

#include <android-base/chrono_utils.h>
#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <android/log.h>
#include <cutils/android_reboot.h>
#include <cutils/properties.h>
#include <log/logcat.h>
#include <metricslogger/metrics_logger.h>

#include "boot_event_record_store.h"

namespace {

// Scans the boot event record store for record files and logs each boot event
// via EventLog.
void LogBootEvents() {
  BootEventRecordStore boot_event_store;

  auto events = boot_event_store.GetAllBootEvents();
  for (auto i = events.cbegin(); i != events.cend(); ++i) {
    android::metricslogger::LogHistogram(i->first, i->second);
  }
}

// Records the named boot |event| to the record store. If |value| is non-empty
// and is a proper string representation of an integer value, the converted
// integer value is associated with the boot event.
void RecordBootEventFromCommandLine(const std::string& event, const std::string& value_str) {
  BootEventRecordStore boot_event_store;
  if (!value_str.empty()) {
    int32_t value = 0;
    if (android::base::ParseInt(value_str, &value)) {
      boot_event_store.AddBootEventWithValue(event, value);
    }
  } else {
    boot_event_store.AddBootEvent(event);
  }
}

void PrintBootEvents() {
  printf("Boot events:\n");
  printf("------------\n");

  BootEventRecordStore boot_event_store;
  auto events = boot_event_store.GetAllBootEvents();
  for (auto i = events.cbegin(); i != events.cend(); ++i) {
    printf("%s\t%d\n", i->first.c_str(), i->second);
  }
}

void ShowHelp(const char* cmd) {
  fprintf(stderr, "Usage: %s [options]\n", cmd);
  fprintf(stderr,
          "options include:\n"
          "  -h, --help              Show this help\n"
          "  -l, --log               Log all metrics to logstorage\n"
          "  -p, --print             Dump the boot event records to the console\n"
          "  -r, --record            Record the timestamp of a named boot event\n"
          "  --value                 Optional value to associate with the boot event\n"
          "  --record_boot_complete  Record metrics related to the time for the device boot\n"
          "  --record_boot_reason    Record the reason why the device booted\n"
          "  --record_time_since_factory_reset Record the time since the device was reset\n");
}

// Constructs a readable, printable string from the givencommand line
// arguments.
std::string GetCommandLine(int argc, char** argv) {
  std::string cmd;
  for (int i = 0; i < argc; ++i) {
    cmd += argv[i];
    cmd += " ";
  }

  return cmd;
}

// Convenience wrapper over the property API that returns an
// std::string.
std::string GetProperty(const char* key) {
  std::vector<char> temp(PROPERTY_VALUE_MAX);
  const int len = property_get(key, &temp[0], nullptr);
  if (len < 0) {
    return "";
  }
  return std::string(&temp[0], len);
}

void SetProperty(const char* key, const std::string& val) {
  property_set(key, val.c_str());
}

void SetProperty(const char* key, const char* val) {
  property_set(key, val);
}

constexpr int32_t kEmptyBootReason = 0;
constexpr int32_t kUnknownBootReason = 1;

// A mapping from boot reason string, as read from the ro.boot.bootreason
// system property, to a unique integer ID. Viewers of log data dashboards for
// the boot_reason metric may refer to this mapping to discern the histogram
// values.
const std::map<std::string, int32_t> kBootReasonMap = {
    {"empty", kEmptyBootReason},
    {"__BOOTSTAT_UNKNOWN__", kUnknownBootReason},
    {"normal", 2},
    {"recovery", 3},
    {"reboot", 4},
    {"PowerKey", 5},
    {"hard_reset", 6},
    {"kernel_panic", 7},
    {"rpm_err", 8},
    {"hw_reset", 9},
    {"tz_err", 10},
    {"adsp_err", 11},
    {"modem_err", 12},
    {"mba_err", 13},
    {"Watchdog", 14},
    {"Panic", 15},
    {"power_key", 16},
    {"power_on", 17},
    {"Reboot", 18},
    {"rtc", 19},
    {"edl", 20},
    {"oem_pon1", 21},
    {"oem_powerkey", 22},
    {"oem_unknown_reset", 23},
    {"srto: HWWDT reset SC", 24},
    {"srto: HWWDT reset platform", 25},
    {"srto: bootloader", 26},
    {"srto: kernel panic", 27},
    {"srto: kernel watchdog reset", 28},
    {"srto: normal", 29},
    {"srto: reboot", 30},
    {"srto: reboot-bootloader", 31},
    {"srto: security watchdog reset", 32},
    {"srto: wakesrc", 33},
    {"srto: watchdog", 34},
    {"srto:1-1", 35},
    {"srto:omap_hsmm", 36},
    {"srto:phy0", 37},
    {"srto:rtc0", 38},
    {"srto:touchpad", 39},
    {"watchdog", 40},
    {"watchdogr", 41},
    {"wdog_bark", 42},
    {"wdog_bite", 43},
    {"wdog_reset", 44},
    {"shutdown,", 45},  // Trailing comma is intentional.
    {"shutdown,userrequested", 46},
    {"reboot,bootloader", 47},
    {"reboot,cold", 48},
    {"reboot,recovery", 49},
    {"thermal_shutdown", 50},
    {"s3_wakeup", 51},
    {"kernel_panic,sysrq", 52},
    {"kernel_panic,NULL", 53},
    {"kernel_panic,null", 53},
    {"kernel_panic,BUG", 54},
    {"kernel_panic,bug", 54},
    {"bootloader", 55},
    {"cold", 56},
    {"hard", 57},
    {"warm", 58},
    {"reboot,kernel_power_off_charging__reboot_system", 59},  // Can not happen
    {"thermal-shutdown", 60},
    {"shutdown,thermal", 61},
    {"shutdown,battery", 62},
    {"reboot,ota", 63},
    {"reboot,factory_reset", 64},
    {"reboot,", 65},
    {"reboot,shell", 66},
    {"reboot,adb", 67},
    {"reboot,userrequested", 68},
    {"shutdown,container", 69},  // Host OS asking Android Container to shutdown
    {"cold,powerkey", 70},
    {"warm,s3_wakeup", 71},
    {"hard,hw_reset", 72},
    {"shutdown,suspend", 73},    // Suspend to RAM
    {"shutdown,hibernate", 74},  // Suspend to DISK
    {"power_on_key", 75},
    {"reboot_by_key", 76},
    {"wdt_by_pass_pwk", 77},
    {"reboot_longkey", 78},
    {"powerkey", 79},
    {"usb", 80},
    {"wdt", 81},
    {"tool_by_pass_pwk", 82},
    {"2sec_reboot", 83},
    {"reboot,by_key", 84},
    {"reboot,longkey", 85},
    {"reboot,2sec", 86},  // Deprecate in two years, replaced with cold,rtc,2sec
    {"shutdown,thermal,battery", 87},
    {"reboot,its_just_so_hard", 88},  // produced by boot_reason_test
    {"reboot,Its Just So Hard", 89},  // produced by boot_reason_test
    {"reboot,rescueparty", 90},
    {"charge", 91},
    {"oem_tz_crash", 92},
    {"uvlo", 93},
    {"oem_ps_hold", 94},
    {"abnormal_reset", 95},
    {"oemerr_unknown", 96},
    {"reboot_fastboot_mode", 97},
    {"watchdog_apps_bite", 98},
    {"xpu_err", 99},
    {"power_on_usb", 100},
    {"watchdog_rpm", 101},
    {"watchdog_nonsec", 102},
    {"watchdog_apps_bark", 103},
    {"reboot_dmverity_corrupted", 104},
    {"reboot_smpl", 105},
    {"watchdog_sdi_apps_reset", 106},
    {"smpl", 107},
    {"oem_modem_failed_to_powerup", 108},
    {"reboot_normal", 109},
    {"oem_lpass_cfg", 110},
    {"oem_xpu_ns_error", 111},
    {"power_key_press", 112},
    {"hardware_reset", 113},
    {"reboot_by_powerkey", 114},
    {"reboot_verity", 115},
    {"oem_rpm_undef_error", 116},
    {"oem_crash_on_the_lk", 117},
    {"oem_rpm_reset", 118},
    {"oem_lpass_cfg", 119},
    {"oem_xpu_ns_error", 120},
    {"factory_cable", 121},
    {"oem_ar6320_failed_to_powerup", 122},
    {"watchdog_rpm_bite", 123},
    {"power_on_cable", 124},
    {"reboot_unknown", 125},
    {"wireless_charger", 126},
    {"0x776655ff", 127},
    {"oem_thermal_bite_reset", 128},
    {"charger", 129},
    {"pon1", 130},
    {"unknown", 131},
    {"reboot_rtc", 132},
    {"cold_boot", 133},
    {"hard_rst", 134},
    {"power-on", 135},
    {"oem_adsp_resetting_the_soc", 136},
    {"kpdpwr", 137},
    {"oem_modem_timeout_waiting", 138},
    {"usb_chg", 139},
    {"warm_reset_0x02", 140},
    {"warm_reset_0x80", 141},
    {"pon_reason_0xb0", 142},
    {"reboot_download", 143},
    {"reboot_recovery_mode", 144},
    {"oem_sdi_err_fatal", 145},
    {"pmic_watchdog", 146},
    {"software_master", 147},
    {"cold,charger", 148},
    {"cold,rtc", 149},
    {"cold,rtc,2sec", 150},
    {"reboot,tool", 151},
    {"reboot,wdt", 152},
    {"reboot,unknown", 153},
    {"kernel_panic,audit", 154},
    {"kernel_panic,atomic", 155},
    {"kernel_panic,hung", 156},
    {"kernel_panic,hung,rcu", 157},
    {"kernel_panic,init", 158},
    {"kernel_panic,oom", 159},
    {"kernel_panic,stack", 160},
    {"kernel_panic,sysrq,livelock,alarm", 161},   // llkd
    {"kernel_panic,sysrq,livelock,driver", 162},  // llkd
    {"kernel_panic,sysrq,livelock,zombie", 163},  // llkd
    {"kernel_panic,modem", 164},
    {"kernel_panic,adsp", 165},
    {"kernel_panic,dsps", 166},
    {"kernel_panic,wcnss", 167},
};

// Converts a string value representing the reason the system booted to an
// integer representation. This is necessary for logging the boot_reason metric
// via Tron, which does not accept non-integer buckets in histograms.
int32_t BootReasonStrToEnum(const std::string& boot_reason) {
  auto mapping = kBootReasonMap.find(boot_reason);
  if (mapping != kBootReasonMap.end()) {
    return mapping->second;
  }

  if (boot_reason.empty()) {
    return kEmptyBootReason;
  }

  LOG(INFO) << "Unknown boot reason: " << boot_reason;
  return kUnknownBootReason;
}

// Canonical list of supported primary reboot reasons.
const std::vector<const std::string> knownReasons = {
    // clang-format off
    // kernel
    "watchdog",
    "kernel_panic",
    // strong
    "recovery",    // Should not happen from ro.boot.bootreason
    "bootloader",  // Should not happen from ro.boot.bootreason
    // blunt
    "cold",
    "hard",
    "warm",
    // super blunt
    "shutdown",    // Can not happen from ro.boot.bootreason
    "reboot",      // Default catch-all for anything unknown
    // clang-format on
};

// Returns true if the supplied reason prefix is considered detailed enough.
bool isStrongRebootReason(const std::string& r) {
  for (auto& s : knownReasons) {
    if (s == "cold") break;
    // Prefix defined as terminated by a nul or comma (,).
    if (android::base::StartsWith(r, s) && ((r.length() == s.length()) || (r[s.length()] == ','))) {
      return true;
    }
  }
  return false;
}

// Returns true if the supplied reason prefix is associated with the kernel.
bool isKernelRebootReason(const std::string& r) {
  for (auto& s : knownReasons) {
    if (s == "recovery") break;
    // Prefix defined as terminated by a nul or comma (,).
    if (android::base::StartsWith(r, s) && ((r.length() == s.length()) || (r[s.length()] == ','))) {
      return true;
    }
  }
  return false;
}

// Returns true if the supplied reason prefix is considered known.
bool isKnownRebootReason(const std::string& r) {
  for (auto& s : knownReasons) {
    // Prefix defined as terminated by a nul or comma (,).
    if (android::base::StartsWith(r, s) && ((r.length() == s.length()) || (r[s.length()] == ','))) {
      return true;
    }
  }
  return false;
}

// If the reboot reason should be improved, report true if is too blunt.
bool isBluntRebootReason(const std::string& r) {
  if (isStrongRebootReason(r)) return false;

  if (!isKnownRebootReason(r)) return true;  // Can not support unknown as detail

  size_t pos = 0;
  while ((pos = r.find(',', pos)) != std::string::npos) {
    ++pos;
    std::string next(r.substr(pos));
    if (next.length() == 0) break;
    if (next[0] == ',') continue;
    if (!isKnownRebootReason(next)) return false;  // Unknown subreason is good.
    if (isStrongRebootReason(next)) return false;  // eg: reboot,reboot
  }
  return true;
}

bool readPstoreConsole(std::string& console) {
  if (android::base::ReadFileToString("/sys/fs/pstore/console-ramoops-0", &console)) {
    return true;
  }
  return android::base::ReadFileToString("/sys/fs/pstore/console-ramoops", &console);
}

// Implement a variant of std::string::rfind that is resilient to errors in
// the data stream being inspected.
class pstoreConsole {
 private:
  const size_t kBitErrorRate = 8;  // number of bits per error
  const std::string& console;

  // Number of bits that differ between the two arguments l and r.
  // Returns zero if the values for l and r are identical.
  size_t numError(uint8_t l, uint8_t r) const { return std::bitset<8>(l ^ r).count(); }

  // A string comparison function, reports the number of errors discovered
  // in the match to a maximum of the bitLength / kBitErrorRate, at that
  // point returning npos to indicate match is too poor.
  //
  // Since called in rfind which works backwards, expect cache locality will
  // help if we check in reverse here as well for performance.
  //
  // Assumption: l (from console.c_str() + pos) is long enough to house
  //             _r.length(), checked in rfind caller below.
  //
  size_t numError(size_t pos, const std::string& _r) const {
    const char* l = console.c_str() + pos;
    const char* r = _r.c_str();
    size_t n = _r.length();
    const uint8_t* le = reinterpret_cast<const uint8_t*>(l) + n;
    const uint8_t* re = reinterpret_cast<const uint8_t*>(r) + n;
    size_t count = 0;
    n = 0;
    do {
      // individual character bit error rate > threshold + slop
      size_t num = numError(*--le, *--re);
      if (num > ((8 + kBitErrorRate) / kBitErrorRate)) return std::string::npos;
      // total bit error rate > threshold + slop
      count += num;
      ++n;
      if (count > ((n * 8 + kBitErrorRate - (n > 2)) / kBitErrorRate)) {
        return std::string::npos;
      }
    } while (le != reinterpret_cast<const uint8_t*>(l));
    return count;
  }

 public:
  explicit pstoreConsole(const std::string& console) : console(console) {}
  // scope of argument must be equal to or greater than scope of pstoreConsole
  explicit pstoreConsole(const std::string&& console) = delete;
  explicit pstoreConsole(std::string&& console) = delete;

  // Our implementation of rfind, use exact match first, then resort to fuzzy.
  size_t rfind(const std::string& needle) const {
    size_t pos = console.rfind(needle);  // exact match?
    if (pos != std::string::npos) return pos;

    // Check to make sure needle fits in console string.
    pos = console.length();
    if (needle.length() > pos) return std::string::npos;
    pos -= needle.length();
    // fuzzy match to maximum kBitErrorRate
    for (;;) {
      if (numError(pos, needle) != std::string::npos) return pos;
      if (pos == 0) break;
      --pos;
    }
    return std::string::npos;
  }

  // Our implementation of find, use only fuzzy match.
  size_t find(const std::string& needle, size_t start = 0) const {
    // Check to make sure needle fits in console string.
    if (needle.length() > console.length()) return std::string::npos;
    const size_t last_pos = console.length() - needle.length();
    // fuzzy match to maximum kBitErrorRate
    for (size_t pos = start; pos <= last_pos; ++pos) {
      if (numError(pos, needle) != std::string::npos) return pos;
    }
    return std::string::npos;
  }

  operator const std::string&() const { return console; }
};

// If bit error match to needle, correct it.
// Return true if any corrections were discovered and applied.
bool correctForBitError(std::string& reason, const std::string& needle) {
  bool corrected = false;
  if (reason.length() < needle.length()) return corrected;
  const pstoreConsole console(reason);
  const size_t last_pos = reason.length() - needle.length();
  for (size_t pos = 0; pos <= last_pos; pos += needle.length()) {
    pos = console.find(needle, pos);
    if (pos == std::string::npos) break;

    // exact match has no malice
    if (needle == reason.substr(pos, needle.length())) continue;

    corrected = true;
    reason = reason.substr(0, pos) + needle + reason.substr(pos + needle.length());
  }
  return corrected;
}

// If bit error match to needle, correct it.
// Return true if any corrections were discovered and applied.
// Try again if we can replace underline with spaces.
bool correctForBitErrorOrUnderline(std::string& reason, const std::string& needle) {
  bool corrected = correctForBitError(reason, needle);
  std::string _needle(needle);
  std::transform(_needle.begin(), _needle.end(), _needle.begin(),
                 [](char c) { return (c == '_') ? ' ' : c; });
  if (needle != _needle) {
    corrected |= correctForBitError(reason, _needle);
  }
  return corrected;
}

// Converts a string value representing the reason the system booted to a
// string complying with Android system standard reason.
void transformReason(std::string& reason) {
  std::transform(reason.begin(), reason.end(), reason.begin(), ::tolower);
  std::transform(reason.begin(), reason.end(), reason.begin(),
                 [](char c) { return ::isblank(c) ? '_' : c; });
  std::transform(reason.begin(), reason.end(), reason.begin(),
                 [](char c) { return ::isprint(c) ? c : '?'; });
}

// Check subreasons for reboot,<subreason> kernel_panic,sysrq,<subreason> or
// kernel_panic,<subreason>.
//
// If quoted flag is set, pull out and correct single quoted ('), newline (\n)
// or unprintable character terminated subreason, pos is supplied just beyond
// first quote.  if quoted false, pull out and correct newline (\n) or
// unprintable character terminated subreason.
//
// Heuristics to find termination is painted into a corner:

// single bit error for quote ' that we can block.  It is acceptable for
// the others 7, g in reason.  2/9 chance will miss the terminating quote,
// but there is always the terminating newline that usually immediately
// follows to fortify our chances.
bool likely_single_quote(char c) {
  switch (static_cast<uint8_t>(c)) {
    case '\'':         // '\''
    case '\'' ^ 0x01:  // '&'
    case '\'' ^ 0x02:  // '%'
    case '\'' ^ 0x04:  // '#'
    case '\'' ^ 0x08:  // '/'
      return true;
    case '\'' ^ 0x10:  // '7'
      break;
    case '\'' ^ 0x20:  // '\a' (unprintable)
      return true;
    case '\'' ^ 0x40:  // 'g'
      break;
    case '\'' ^ 0x80:  // 0xA7 (unprintable)
      return true;
  }
  return false;
}

// ::isprint(c) and likely_space() will prevent us from being called for
// fundamentally printable entries, except for '\r' and '\b'.
//
// Except for * and J, single bit errors for \n, all others are non-
// printable so easy catch.  It is _acceptable_ for *, J or j to exist in
// the reason string, so 2/9 chance we will miss the terminating newline.
//
// NB: J might not be acceptable, except if at the beginning or preceded
//     with a space, '(' or any of the quotes and their BER aliases.
// NB: * might not be acceptable, except if at the beginning or preceded
//     with a space, another *, or any of the quotes or their BER aliases.
//
// To reduce the chances to closer to 1/9 is too complicated for the gain.
bool likely_newline(char c) {
  switch (static_cast<uint8_t>(c)) {
    case '\n':         // '\n' (unprintable)
    case '\n' ^ 0x01:  // '\r' (unprintable)
    case '\n' ^ 0x02:  // '\b' (unprintable)
    case '\n' ^ 0x04:  // 0x0E (unprintable)
    case '\n' ^ 0x08:  // 0x02 (unprintable)
    case '\n' ^ 0x10:  // 0x1A (unprintable)
      return true;
    case '\n' ^ 0x20:  // '*'
    case '\n' ^ 0x40:  // 'J'
      break;
    case '\n' ^ 0x80:  // 0x8A (unprintable)
      return true;
  }
  return false;
}

// ::isprint(c) will prevent us from being called for all the printable
// matches below.  If we let unprintables through because of this, they
// get converted to underscore (_) by the validation phase.
bool likely_space(char c) {
  switch (static_cast<uint8_t>(c)) {
    case ' ':          // ' '
    case ' ' ^ 0x01:   // '!'
    case ' ' ^ 0x02:   // '"'
    case ' ' ^ 0x04:   // '$'
    case ' ' ^ 0x08:   // '('
    case ' ' ^ 0x10:   // '0'
    case ' ' ^ 0x20:   // '\0' (unprintable)
    case ' ' ^ 0x40:   // 'P'
    case ' ' ^ 0x80:   // 0xA0 (unprintable)
    case '\t':         // '\t'
    case '\t' ^ 0x01:  // '\b' (unprintable) (likely_newline counters)
    case '\t' ^ 0x02:  // '\v' (unprintable)
    case '\t' ^ 0x04:  // '\r' (unprintable) (likely_newline counters)
    case '\t' ^ 0x08:  // 0x01 (unprintable)
    case '\t' ^ 0x10:  // 0x19 (unprintable)
    case '\t' ^ 0x20:  // ')'
    case '\t' ^ 0x40:  // '1'
    case '\t' ^ 0x80:  // 0x89 (unprintable)
      return true;
  }
  return false;
}

std::string getSubreason(const std::string& content, size_t pos, bool quoted) {
  static constexpr size_t max_reason_length = 256;

  std::string subReason(content.substr(pos, max_reason_length));
  // Correct against any known strings that Bit Error Match
  for (const auto& s : knownReasons) {
    correctForBitErrorOrUnderline(subReason, s);
  }
  std::string terminator(quoted ? "'" : "");
  for (const auto& m : kBootReasonMap) {
    if (m.first.length() <= strlen("cold")) continue;  // too short?
    if (correctForBitErrorOrUnderline(subReason, m.first + terminator)) continue;
    if (m.first.length() <= strlen("reboot,cold")) continue;  // short?
    if (android::base::StartsWith(m.first, "reboot,")) {
      correctForBitErrorOrUnderline(subReason, m.first.substr(strlen("reboot,")) + terminator);
    } else if (android::base::StartsWith(m.first, "kernel_panic,sysrq,")) {
      correctForBitErrorOrUnderline(subReason,
                                    m.first.substr(strlen("kernel_panic,sysrq,")) + terminator);
    } else if (android::base::StartsWith(m.first, "kernel_panic,")) {
      correctForBitErrorOrUnderline(subReason, m.first.substr(strlen("kernel_panic,")) + terminator);
    }
  }
  for (pos = 0; pos < subReason.length(); ++pos) {
    char c = subReason[pos];
    if (!(::isprint(c) || likely_space(c)) || likely_newline(c) ||
        (quoted && likely_single_quote(c))) {
      subReason.erase(pos);
      break;
    }
  }
  transformReason(subReason);
  return subReason;
}

bool addKernelPanicSubReason(const pstoreConsole& console, std::string& ret) {
  // Check for kernel panic types to refine information
  if ((console.rfind("SysRq : Trigger a crash") != std::string::npos) ||
      (console.rfind("PC is at sysrq_handle_crash+") != std::string::npos)) {
    ret = "kernel_panic,sysrq";
    // Invented for Android to allow daemons that specifically trigger sysrq
    // to communicate more accurate boot subreasons via last console messages.
    static constexpr char sysrqSubreason[] = "SysRq : Trigger a crash : '";
    auto pos = console.rfind(sysrqSubreason);
    if (pos != std::string::npos) {
      ret += "," + getSubreason(console, pos + strlen(sysrqSubreason), /* quoted */ true);
    }
    return true;
  }
  if (console.rfind("Unable to handle kernel NULL pointer dereference at virtual address") !=
      std::string::npos) {
    ret = "kernel_panic,null";
    return true;
  }
  if (console.rfind("Kernel BUG at ") != std::string::npos) {
    ret = "kernel_panic,bug";
    return true;
  }

  std::string panic("Kernel panic - not syncing: ");
  auto pos = console.rfind(panic);
  if (pos != std::string::npos) {
    static const std::vector<std::pair<const std::string, const std::string>> panicReasons = {
        {"Out of memory", "oom"},
        {"out of memory", "oom"},
        {"Oh boy, that early out of memory", "oom"},  // omg
        {"BUG!", "bug"},
        {"hung_task: blocked tasks", "hung"},
        {"audit: ", "audit"},
        {"scheduling while atomic", "atomic"},
        {"Attempted to kill init!", "init"},
        {"Requested init", "init"},
        {"No working init", "init"},
        {"Could not decompress init", "init"},
        {"RCU Stall", "hung,rcu"},
        {"stack-protector", "stack"},
        {"kernel stack overflow", "stack"},
        {"Corrupt kernel stack", "stack"},
        {"low stack detected", "stack"},
        {"corrupted stack end", "stack"},
        {"subsys-restart: Resetting the SoC - modem crashed.", "modem"},
        {"subsys-restart: Resetting the SoC - adsp crashed.", "adsp"},
        {"subsys-restart: Resetting the SoC - dsps crashed.", "dsps"},
        {"subsys-restart: Resetting the SoC - wcnss crashed.", "wcnss"},
    };

    ret = "kernel_panic";
    for (auto& s : panicReasons) {
      if (console.find(panic + s.first, pos) != std::string::npos) {
        ret += "," + s.second;
        return true;
      }
    }
    auto reason = getSubreason(console, pos + panic.length(), /* newline */ false);
    if (reason.length() > 3) {
      ret += "," + reason;
    }
    return true;
  }
  return false;
}

bool addKernelPanicSubReason(const std::string& content, std::string& ret) {
  return addKernelPanicSubReason(pstoreConsole(content), ret);
}

const char system_reboot_reason_property[] = "sys.boot.reason";
const char last_reboot_reason_property[] = LAST_REBOOT_REASON_PROPERTY;
const char bootloader_reboot_reason_property[] = "ro.boot.bootreason";

// Scrub, Sanitize, Standardize and Enhance the boot reason string supplied.
std::string BootReasonStrToReason(const std::string& boot_reason) {
  std::string ret(GetProperty(system_reboot_reason_property));
  std::string reason(boot_reason);
  // If sys.boot.reason == ro.boot.bootreason, let's re-evaluate
  if (reason == ret) ret = "";

  transformReason(reason);

  // Is the current system boot reason sys.boot.reason valid?
  if (!isKnownRebootReason(ret)) ret = "";

  if (ret == "") {
    // Is the bootloader boot reason ro.boot.bootreason known?
    std::vector<std::string> words(android::base::Split(reason, ",_-"));
    for (auto& s : knownReasons) {
      std::string blunt;
      for (auto& r : words) {
        if (r == s) {
          if (isBluntRebootReason(s)) {
            blunt = s;
          } else {
            ret = s;
            break;
          }
        }
      }
      if (ret == "") ret = blunt;
      if (ret != "") break;
    }
  }

  if (ret == "") {
    // A series of checks to take some officially unsupported reasons
    // reported by the bootloader and find some logical and canonical
    // sense.  In an ideal world, we would require those bootloaders
    // to behave and follow our CTS standards.
    //
    // first member is the output
    // second member is an unanchored regex for an alias
    //
    // If output has a prefix of <bang> '!', we do not use it as a
    // match needle (and drop the <bang> prefix when landing in output),
    // otherwise look for it as well. This helps keep the scale of the
    // following table smaller.
    static const std::vector<std::pair<const std::string, const std::string>> aliasReasons = {
        {"watchdog", "wdog"},
        {"cold,powerkey", "powerkey|power_key|PowerKey"},
        {"kernel_panic", "panic"},
        {"shutdown,thermal", "thermal"},
        {"warm,s3_wakeup", "s3_wakeup"},
        {"hard,hw_reset", "hw_reset"},
        {"cold,charger", "usb"},
        {"cold,rtc", "rtc"},
        {"cold,rtc,2sec", "2sec_reboot"},
        {"!warm", "wdt_by_pass_pwk"},  // change flavour of blunt
        {"!reboot", "^wdt$"},          // change flavour of blunt
        {"reboot,tool", "tool_by_pass_pwk"},
        {"bootloader", ""},
    };

    for (auto& s : aliasReasons) {
      size_t firstHasNot = s.first[0] == '!';
      if (!firstHasNot && (reason.find(s.first) != std::string::npos)) {
        ret = s.first;
        break;
      }
      if (s.second.size() && std::regex_search(reason, std::regex(s.second))) {
        ret = s.first.substr(firstHasNot);
        break;
      }
    }
  }

  // If watchdog is the reason, see if there is a security angle?
  if (ret == "watchdog") {
    if (reason.find("sec") != std::string::npos) {
      ret += ",security";
    }
  }

  if (ret == "kernel_panic") {
    // Check to see if last klog has some refinement hints.
    std::string content;
    if (readPstoreConsole(content)) {
      addKernelPanicSubReason(content, ret);
    }
  } else if (isBluntRebootReason(ret)) {
    // Check the other available reason resources if the reason is still blunt.

    // Check to see if last klog has some refinement hints.
    std::string content;
    if (readPstoreConsole(content)) {
      const pstoreConsole console(content);
      // The toybox reboot command used directly (unlikely)? But also
      // catches init's response to Android's more controlled reboot command.
      if (console.rfind("reboot: Power down") != std::string::npos) {
        ret = "shutdown";  // Still too blunt, but more accurate.
        // ToDo: init should record the shutdown reason to kernel messages ala:
        //           init: shutdown system with command 'last_reboot_reason'
        //       so that if pstore has persistence we can get some details
        //       that could be missing in last_reboot_reason_property.
      }

      static const char cmd[] = "reboot: Restarting system with command '";
      size_t pos = console.rfind(cmd);
      if (pos != std::string::npos) {
        std::string subReason(getSubreason(content, pos + strlen(cmd), /* quoted */ true));
        if (subReason != "") {  // Will not land "reboot" as that is too blunt.
          if (isKernelRebootReason(subReason)) {
            ret = "reboot," + subReason;  // User space can't talk kernel reasons.
          } else if (isKnownRebootReason(subReason)) {
            ret = subReason;
          } else {
            ret = "reboot," + subReason;  // legitimize unknown reasons
          }
        }
        // Some bootloaders shutdown results record in last kernel message.
        if (!strcmp(ret.c_str(), "reboot,kernel_power_off_charging__reboot_system")) {
          ret = "shutdown";
        }
      }

      // Check for kernel panics, allowed to override reboot command.
      if (!addKernelPanicSubReason(console, ret) &&
          // check for long-press power down
          ((console.rfind("Power held for ") != std::string::npos) ||
           (console.rfind("charger: [") != std::string::npos))) {
        ret = "cold";
      }
    }

    // The following battery test should migrate to a default system health HAL

    // Let us not worry if the reboot command was issued, for the cases of
    // reboot -p, reboot <no reason>, reboot cold, reboot warm and reboot hard.
    // Same for bootloader and ro.boot.bootreasons of this set, but a dead
    // battery could conceivably lead to these, so worthy of override.
    if (isBluntRebootReason(ret)) {
      // Heuristic to determine if shutdown possibly because of a dead battery?
      // Really a hail-mary pass to find it in last klog content ...
      static const int battery_dead_threshold = 2;  // percent
      static const char battery[] = "healthd: battery l=";
      const pstoreConsole console(content);
      size_t pos = console.rfind(battery);  // last one
      std::string digits;
      if (pos != std::string::npos) {
        digits = content.substr(pos + strlen(battery), strlen("100 "));
        // correct common errors
        correctForBitError(digits, "100 ");
        if (digits[0] == '!') digits[0] = '1';
        if (digits[1] == '!') digits[1] = '1';
      }
      const char* endptr = digits.c_str();
      unsigned level = 0;
      while (::isdigit(*endptr)) {
        level *= 10;
        level += *endptr++ - '0';
        // make sure no leading zeros, except zero itself, and range check.
        if ((level == 0) || (level > 100)) break;
      }
      // example bit error rate issues for 10%
      //   'l=10 ' no bits in error
      //   'l=00 ' single bit error (fails above)
      //   'l=1  ' single bit error
      //   'l=0  ' double bit error
      // There are others, not typically critical because of 2%
      // battery_dead_threshold. KISS check, make sure second
      // character after digit sequence is not a space.
      if ((level <= 100) && (endptr != digits.c_str()) && (endptr[0] == ' ') && (endptr[1] != ' ')) {
        LOG(INFO) << "Battery level at shutdown " << level << "%";
        if (level <= battery_dead_threshold) {
          ret = "shutdown,battery";
        }
      } else {        // Most likely
        digits = "";  // reset digits

        // Content buffer no longer will have console data. Beware if more
        // checks added below, that depend on parsing console content.
        content = "";

        LOG(DEBUG) << "Can not find last low battery in last console messages";
        android_logcat_context ctx = create_android_logcat();
        FILE* fp = android_logcat_popen(&ctx, "logcat -b kernel -v brief -d");
        if (fp != nullptr) {
          android::base::ReadFdToString(fileno(fp), &content);
        }
        android_logcat_pclose(&ctx, fp);
        static const char logcat_battery[] = "W/healthd (    0): battery l=";
        const char* match = logcat_battery;

        if (content == "") {
          // Service logd.klog not running, go to smaller buffer in the kernel.
          int rc = klogctl(KLOG_SIZE_BUFFER, nullptr, 0);
          if (rc > 0) {
            ssize_t len = rc + 1024;  // 1K Margin should it grow between calls.
            std::unique_ptr<char[]> buf(new char[len]);
            rc = klogctl(KLOG_READ_ALL, buf.get(), len);
            if (rc < len) {
              len = rc + 1;
            }
            buf[--len] = '\0';
            content = buf.get();
          }
          match = battery;
        }

        pos = content.find(match);  // The first one it finds.
        if (pos != std::string::npos) {
          digits = content.substr(pos + strlen(match), strlen("100 "));
        }
        endptr = digits.c_str();
        level = 0;
        while (::isdigit(*endptr)) {
          level *= 10;
          level += *endptr++ - '0';
          // make sure no leading zeros, except zero itself, and range check.
          if ((level == 0) || (level > 100)) break;
        }
        if ((level <= 100) && (endptr != digits.c_str()) && (*endptr == ' ')) {
          LOG(INFO) << "Battery level at startup " << level << "%";
          if (level <= battery_dead_threshold) {
            ret = "shutdown,battery";
          }
        } else {
          LOG(DEBUG) << "Can not find first battery level in dmesg or logcat";
        }
      }
    }

    // Is there a controlled shutdown hint in last_reboot_reason_property?
    if (isBluntRebootReason(ret)) {
      // Content buffer no longer will have console data. Beware if more
      // checks added below, that depend on parsing console content.
      content = GetProperty(last_reboot_reason_property);
      transformReason(content);

      // Anything in last is better than 'super-blunt' reboot or shutdown.
      if ((ret == "") || (ret == "reboot") || (ret == "shutdown") || !isBluntRebootReason(content)) {
        ret = content;
      }
    }

    // Other System Health HAL reasons?

    // ToDo: /proc/sys/kernel/boot_reason needs a HAL interface to
    //       possibly offer hardware-specific clues from the PMIC.
  }

  // If unknown left over from above, make it "reboot,<boot_reason>"
  if (ret == "") {
    ret = "reboot";
    if (android::base::StartsWith(reason, "reboot")) {
      reason = reason.substr(strlen("reboot"));
      while ((reason[0] == ',') || (reason[0] == '_')) {
        reason = reason.substr(1);
      }
    }
    if (reason != "") {
      ret += ",";
      ret += reason;
    }
  }

  LOG(INFO) << "Canonical boot reason: " << ret;
  if (isKernelRebootReason(ret) && (GetProperty(last_reboot_reason_property) != "")) {
    // Rewrite as it must be old news, kernel reasons trump user space.
    SetProperty(last_reboot_reason_property, ret);
  }
  return ret;
}

// Returns the appropriate metric key prefix for the boot_complete metric such
// that boot metrics after a system update are labeled as ota_boot_complete;
// otherwise, they are labeled as boot_complete.  This method encapsulates the
// bookkeeping required to track when a system update has occurred by storing
// the UTC timestamp of the system build date and comparing against the current
// system build date.
std::string CalculateBootCompletePrefix() {
  static const std::string kBuildDateKey = "build_date";
  std::string boot_complete_prefix = "boot_complete";

  std::string build_date_str = GetProperty("ro.build.date.utc");
  int32_t build_date;
  if (!android::base::ParseInt(build_date_str, &build_date)) {
    return std::string();
  }

  BootEventRecordStore boot_event_store;
  BootEventRecordStore::BootEventRecord record;
  if (!boot_event_store.GetBootEvent(kBuildDateKey, &record)) {
    boot_complete_prefix = "factory_reset_" + boot_complete_prefix;
    boot_event_store.AddBootEventWithValue(kBuildDateKey, build_date);
    LOG(INFO) << "Canonical boot reason: reboot,factory_reset";
    SetProperty(system_reboot_reason_property, "reboot,factory_reset");
  } else if (build_date != record.second) {
    boot_complete_prefix = "ota_" + boot_complete_prefix;
    boot_event_store.AddBootEventWithValue(kBuildDateKey, build_date);
    LOG(INFO) << "Canonical boot reason: reboot,ota";
    SetProperty(system_reboot_reason_property, "reboot,ota");
  }

  return boot_complete_prefix;
}

// Records the value of a given ro.boottime.init property in milliseconds.
void RecordInitBootTimeProp(BootEventRecordStore* boot_event_store, const char* property) {
  std::string value = GetProperty(property);

  int32_t time_in_ms;
  if (android::base::ParseInt(value, &time_in_ms)) {
    boot_event_store->AddBootEventWithValue(property, time_in_ms);
  }
}

// A map from bootloader timing stage to the time that stage took during boot.
typedef std::map<std::string, int32_t> BootloaderTimingMap;

// Returns a mapping from bootloader stage names to the time those stages
// took to boot.
const BootloaderTimingMap GetBootLoaderTimings() {
  BootloaderTimingMap timings;

  // |ro.boot.boottime| is of the form 'stage1:time1,...,stageN:timeN',
  // where timeN is in milliseconds.
  std::string value = GetProperty("ro.boot.boottime");
  if (value.empty()) {
    // ro.boot.boottime is not reported on all devices.
    return BootloaderTimingMap();
  }

  auto stages = android::base::Split(value, ",");
  for (const auto& stageTiming : stages) {
    // |stageTiming| is of the form 'stage:time'.
    auto stageTimingValues = android::base::Split(stageTiming, ":");
    DCHECK_EQ(2U, stageTimingValues.size());

    std::string stageName = stageTimingValues[0];
    int32_t time_ms;
    if (android::base::ParseInt(stageTimingValues[1], &time_ms)) {
      timings[stageName] = time_ms;
    }
  }

  return timings;
}

// Parses and records the set of bootloader stages and associated boot times
// from the ro.boot.boottime system property.
void RecordBootloaderTimings(BootEventRecordStore* boot_event_store,
                             const BootloaderTimingMap& bootloader_timings) {
  int32_t total_time = 0;
  for (const auto& timing : bootloader_timings) {
    total_time += timing.second;
    boot_event_store->AddBootEventWithValue("boottime.bootloader." + timing.first, timing.second);
  }

  boot_event_store->AddBootEventWithValue("boottime.bootloader.total", total_time);
}

// Records the closest estimation to the absolute device boot time, i.e.,
// from power on to boot_complete, including bootloader times.
void RecordAbsoluteBootTime(BootEventRecordStore* boot_event_store,
                            const BootloaderTimingMap& bootloader_timings,
                            std::chrono::milliseconds uptime) {
  int32_t bootloader_time_ms = 0;

  for (const auto& timing : bootloader_timings) {
    if (timing.first.compare("SW") != 0) {
      bootloader_time_ms += timing.second;
    }
  }

  auto bootloader_duration = std::chrono::milliseconds(bootloader_time_ms);
  auto absolute_total =
      std::chrono::duration_cast<std::chrono::seconds>(bootloader_duration + uptime);
  boot_event_store->AddBootEventWithValue("absolute_boot_time", absolute_total.count());
}

// Gets the boot time offset. This is useful when Android is running in a
// container, because the boot_clock is not reset when Android reboots.
std::chrono::nanoseconds GetBootTimeOffset() {
  static const int64_t boottime_offset =
      android::base::GetIntProperty<int64_t>("ro.boot.boottime_offset", 0);
  return std::chrono::nanoseconds(boottime_offset);
}

// Returns the current uptime, accounting for any offset in the CLOCK_BOOTTIME
// clock.
android::base::boot_clock::duration GetUptime() {
  return android::base::boot_clock::now().time_since_epoch() - GetBootTimeOffset();
}

void SetSystemBootReason() {
  const std::string bootloader_boot_reason(GetProperty(bootloader_reboot_reason_property));
  const std::string system_boot_reason(BootReasonStrToReason(bootloader_boot_reason));
  // Record the scrubbed system_boot_reason to the property
  SetProperty(system_reboot_reason_property, system_boot_reason);
}

// Records several metrics related to the time it takes to boot the device,
// including disambiguating boot time on encrypted or non-encrypted devices.
void RecordBootComplete() {
  BootEventRecordStore boot_event_store;
  BootEventRecordStore::BootEventRecord record;

  auto uptime_ns = GetUptime();
  auto uptime_s = std::chrono::duration_cast<std::chrono::seconds>(uptime_ns);
  time_t current_time_utc = time(nullptr);

  if (boot_event_store.GetBootEvent("last_boot_time_utc", &record)) {
    time_t last_boot_time_utc = record.second;
    time_t time_since_last_boot = difftime(current_time_utc, last_boot_time_utc);
    boot_event_store.AddBootEventWithValue("time_since_last_boot", time_since_last_boot);
  }

  boot_event_store.AddBootEventWithValue("last_boot_time_utc", current_time_utc);

  // The boot_complete metric has two variants: boot_complete and
  // ota_boot_complete.  The latter signifies that the device is booting after
  // a system update.
  std::string boot_complete_prefix = CalculateBootCompletePrefix();
  if (boot_complete_prefix.empty()) {
    // The system is hosed because the build date property could not be read.
    return;
  }

  // post_decrypt_time_elapsed is only logged on encrypted devices.
  if (boot_event_store.GetBootEvent("post_decrypt_time_elapsed", &record)) {
    // Log the amount of time elapsed until the device is decrypted, which
    // includes the variable amount of time the user takes to enter the
    // decryption password.
    boot_event_store.AddBootEventWithValue("boot_decryption_complete", uptime_s.count());

    // Subtract the decryption time to normalize the boot cycle timing.
    std::chrono::seconds boot_complete = std::chrono::seconds(uptime_s.count() - record.second);
    boot_event_store.AddBootEventWithValue(boot_complete_prefix + "_post_decrypt",
                                           boot_complete.count());
  } else {
    boot_event_store.AddBootEventWithValue(boot_complete_prefix + "_no_encryption",
                                           uptime_s.count());
  }

  // Record the total time from device startup to boot complete, regardless of
  // encryption state.
  boot_event_store.AddBootEventWithValue(boot_complete_prefix, uptime_s.count());

  RecordInitBootTimeProp(&boot_event_store, "ro.boottime.init");
  RecordInitBootTimeProp(&boot_event_store, "ro.boottime.init.selinux");
  RecordInitBootTimeProp(&boot_event_store, "ro.boottime.init.cold_boot_wait");

  const BootloaderTimingMap bootloader_timings = GetBootLoaderTimings();
  RecordBootloaderTimings(&boot_event_store, bootloader_timings);

  auto uptime_ms = std::chrono::duration_cast<std::chrono::milliseconds>(uptime_ns);
  RecordAbsoluteBootTime(&boot_event_store, bootloader_timings, uptime_ms);
}

// Records the boot_reason metric by querying the ro.boot.bootreason system
// property.
void RecordBootReason() {
  const std::string reason(GetProperty(bootloader_reboot_reason_property));

  if (reason.empty()) {
    // Log an empty boot reason value as '<EMPTY>' to ensure the value is intentional
    // (and not corruption anywhere else in the reporting pipeline).
    android::metricslogger::LogMultiAction(android::metricslogger::ACTION_BOOT,
                                           android::metricslogger::FIELD_PLATFORM_REASON, "<EMPTY>");
  } else {
    android::metricslogger::LogMultiAction(android::metricslogger::ACTION_BOOT,
                                           android::metricslogger::FIELD_PLATFORM_REASON, reason);
  }

  // Log the raw bootloader_boot_reason property value.
  int32_t boot_reason = BootReasonStrToEnum(reason);
  BootEventRecordStore boot_event_store;
  boot_event_store.AddBootEventWithValue("boot_reason", boot_reason);

  // Log the scrubbed system_boot_reason.
  const std::string system_reason(GetProperty(system_reboot_reason_property));
  int32_t system_boot_reason = BootReasonStrToEnum(system_reason);
  boot_event_store.AddBootEventWithValue("system_boot_reason", system_boot_reason);

  if (reason == "") {
    SetProperty(bootloader_reboot_reason_property, system_reason);
  }
}

// Records two metrics related to the user resetting a device: the time at
// which the device is reset, and the time since the user last reset the
// device.  The former is only set once per-factory reset.
void RecordFactoryReset() {
  BootEventRecordStore boot_event_store;
  BootEventRecordStore::BootEventRecord record;

  time_t current_time_utc = time(nullptr);

  if (current_time_utc < 0) {
    // UMA does not display negative values in buckets, so convert to positive.
    android::metricslogger::LogHistogram("factory_reset_current_time_failure",
                                         std::abs(current_time_utc));

    // Logging via BootEventRecordStore to see if using android::metricslogger::LogHistogram
    // is losing records somehow.
    boot_event_store.AddBootEventWithValue("factory_reset_current_time_failure",
                                           std::abs(current_time_utc));
    return;
  } else {
    android::metricslogger::LogHistogram("factory_reset_current_time", current_time_utc);

    // Logging via BootEventRecordStore to see if using android::metricslogger::LogHistogram
    // is losing records somehow.
    boot_event_store.AddBootEventWithValue("factory_reset_current_time", current_time_utc);
  }

  // The factory_reset boot event does not exist after the device is reset, so
  // use this signal to mark the time of the factory reset.
  if (!boot_event_store.GetBootEvent("factory_reset", &record)) {
    boot_event_store.AddBootEventWithValue("factory_reset", current_time_utc);

    // Don't log the time_since_factory_reset until some time has elapsed.
    // The data is not meaningful yet and skews the histogram buckets.
    return;
  }

  // Calculate and record the difference in time between now and the
  // factory_reset time.
  time_t factory_reset_utc = record.second;
  android::metricslogger::LogHistogram("factory_reset_record_value", factory_reset_utc);

  // Logging via BootEventRecordStore to see if using android::metricslogger::LogHistogram
  // is losing records somehow.
  boot_event_store.AddBootEventWithValue("factory_reset_record_value", factory_reset_utc);

  time_t time_since_factory_reset = difftime(current_time_utc, factory_reset_utc);
  boot_event_store.AddBootEventWithValue("time_since_factory_reset", time_since_factory_reset);
}

}  // namespace

int main(int argc, char** argv) {
  android::base::InitLogging(argv);

  const std::string cmd_line = GetCommandLine(argc, argv);
  LOG(INFO) << "Service started: " << cmd_line;

  int option_index = 0;
  static const char value_str[] = "value";
  static const char system_boot_reason_str[] = "set_system_boot_reason";
  static const char boot_complete_str[] = "record_boot_complete";
  static const char boot_reason_str[] = "record_boot_reason";
  static const char factory_reset_str[] = "record_time_since_factory_reset";
  static const struct option long_options[] = {
      // clang-format off
      { "help",                 no_argument,       NULL,   'h' },
      { "log",                  no_argument,       NULL,   'l' },
      { "print",                no_argument,       NULL,   'p' },
      { "record",               required_argument, NULL,   'r' },
      { value_str,              required_argument, NULL,   0 },
      { system_boot_reason_str, no_argument,       NULL,   0 },
      { boot_complete_str,      no_argument,       NULL,   0 },
      { boot_reason_str,        no_argument,       NULL,   0 },
      { factory_reset_str,      no_argument,       NULL,   0 },
      { NULL,                   0,                 NULL,   0 }
      // clang-format on
  };

  std::string boot_event;
  std::string value;
  int opt = 0;
  while ((opt = getopt_long(argc, argv, "hlpr:", long_options, &option_index)) != -1) {
    switch (opt) {
      // This case handles long options which have no single-character mapping.
      case 0: {
        const std::string option_name = long_options[option_index].name;
        if (option_name == value_str) {
          // |optarg| is an external variable set by getopt representing
          // the option argument.
          value = optarg;
        } else if (option_name == system_boot_reason_str) {
          SetSystemBootReason();
        } else if (option_name == boot_complete_str) {
          RecordBootComplete();
        } else if (option_name == boot_reason_str) {
          RecordBootReason();
        } else if (option_name == factory_reset_str) {
          RecordFactoryReset();
        } else {
          LOG(ERROR) << "Invalid option: " << option_name;
        }
        break;
      }

      case 'h': {
        ShowHelp(argv[0]);
        break;
      }

      case 'l': {
        LogBootEvents();
        break;
      }

      case 'p': {
        PrintBootEvents();
        break;
      }

      case 'r': {
        // |optarg| is an external variable set by getopt representing
        // the option argument.
        boot_event = optarg;
        break;
      }

      default: {
        DCHECK_EQ(opt, '?');

        // |optopt| is an external variable set by getopt representing
        // the value of the invalid option.
        LOG(ERROR) << "Invalid option: " << optopt;
        ShowHelp(argv[0]);
        return EXIT_FAILURE;
      }
    }
  }

  if (!boot_event.empty()) {
    RecordBootEventFromCommandLine(boot_event, value);
  }

  return 0;
}

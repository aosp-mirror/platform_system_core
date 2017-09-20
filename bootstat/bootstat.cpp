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
#include <unistd.h>
#include <sys/klog.h>

#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdio>
#include <ctime>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include <android-base/chrono_utils.h>
#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/parseint.h>
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
void RecordBootEventFromCommandLine(
    const std::string& event, const std::string& value_str) {
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

void ShowHelp(const char *cmd) {
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
std::string GetCommandLine(int argc, char **argv) {
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

constexpr int32_t kUnknownBootReason = 1;

// A mapping from boot reason string, as read from the ro.boot.bootreason
// system property, to a unique integer ID. Viewers of log data dashboards for
// the boot_reason metric may refer to this mapping to discern the histogram
// values.
const std::map<std::string, int32_t> kBootReasonMap = {
  {"unknown", kUnknownBootReason},
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
  {"kernel_panic,BUG", 54},
  {"bootloader", 55},
  {"cold", 56},
  {"hard", 57},
  {"warm", 58},
  {"recovery", 59},
  {"thermal-shutdown", 60},
  {"shutdown,thermal", 61},
  {"shutdown,battery", 62},
  {"reboot,ota", 63},
  {"reboot,factory_reset", 64},
  {"reboot,", 65},
  {"reboot,shell", 66},
  {"reboot,adb", 67},
};

// Converts a string value representing the reason the system booted to an
// integer representation. This is necessary for logging the boot_reason metric
// via Tron, which does not accept non-integer buckets in histograms.
int32_t BootReasonStrToEnum(const std::string& boot_reason) {
  auto mapping = kBootReasonMap.find(boot_reason);
  if (mapping != kBootReasonMap.end()) {
    return mapping->second;
  }

  LOG(INFO) << "Unknown boot reason: " << boot_reason;
  return kUnknownBootReason;
}

// Canonical list of supported primary reboot reasons.
const std::vector<const std::string> knownReasons = {
  // kernel
  "watchdog",
  "kernel_panic",
  // strong
  "recovery",      // Should not happen from ro.boot.bootreason
  "bootloader",    // Should not happen from ro.boot.bootreason
  // blunt
  "cold",
  "hard",
  "warm",
  "shutdown",      // Can not happen from ro.boot.bootreason
  "reboot",        // Default catch-all for anything unknown
};

// Returns true if the supplied reason prefix is considered detailed enough.
bool isStrongRebootReason(const std::string& r) {
  for (auto &s : knownReasons) {
    if (s == "cold") break;
    // Prefix defined as terminated by a nul or comma (,).
    if (android::base::StartsWith(r, s.c_str()) &&
        ((r.length() == s.length()) || (r[s.length()] == ','))) {
      return true;
    }
  }
  return false;
}

// Returns true if the supplied reason prefix is associated with the kernel.
bool isKernelRebootReason(const std::string& r) {
  for (auto &s : knownReasons) {
    if (s == "recovery") break;
    // Prefix defined as terminated by a nul or comma (,).
    if (android::base::StartsWith(r, s.c_str()) &&
        ((r.length() == s.length()) || (r[s.length()] == ','))) {
      return true;
    }
  }
  return false;
}

// Returns true if the supplied reason prefix is considered known.
bool isKnownRebootReason(const std::string& r) {
  for (auto &s : knownReasons) {
    // Prefix defined as terminated by a nul or comma (,).
    if (android::base::StartsWith(r, s.c_str()) &&
        ((r.length() == s.length()) || (r[s.length()] == ','))) {
      return true;
    }
  }
  return false;
}

// If the reboot reason should be improved, report true if is too blunt.
bool isBluntRebootReason(const std::string& r) {
  if (isStrongRebootReason(r)) return false;

  if (!isKnownRebootReason(r)) return true; // Can not support unknown as detail

  size_t pos = 0;
  while ((pos = r.find(',', pos)) != std::string::npos) {
    ++pos;
    std::string next(r.substr(pos));
    if (next.length() == 0) break;
    if (next[0] == ',') continue;
    if (!isKnownRebootReason(next)) return false; // Unknown subreason is good.
    if (isStrongRebootReason(next)) return false; // eg: reboot,reboot
  }
  return true;
}

// std::transform Helper callback functions:
// Converts a string value representing the reason the system booted to a
// string complying with Android system standard reason.
char tounderline(char c) { return ::isblank(c) ? '_' : c; }
char toprintable(char c) { return ::isprint(c) ? c : '?'; }

const char system_reboot_reason_property[] = "sys.boot.reason";
const char last_reboot_reason_property[] = LAST_REBOOT_REASON_PROPERTY;
const char bootloader_reboot_reason_property[] = "ro.boot.bootreason";

// Scrub, Sanitize, Standardize and Enhance the boot reason string supplied.
std::string BootReasonStrToReason(const std::string& boot_reason) {
  std::string ret(GetProperty(system_reboot_reason_property));
  std::string reason(boot_reason);
  // If sys.boot.reason == ro.boot.bootreason, let's re-evaluate
  if (reason == ret) ret = "";

  // Cleanup boot_reason regarding acceptable character set
  std::transform(reason.begin(), reason.end(), reason.begin(), ::tolower);
  std::transform(reason.begin(), reason.end(), reason.begin(), tounderline);
  std::transform(reason.begin(), reason.end(), reason.begin(), toprintable);

  // Is the current system boot reason sys.boot.reason valid?
  if (!isKnownRebootReason(ret)) ret = "";

  if (ret == "") {
    // Is the bootloader boot reason ro.boot.bootreason known?
    std::vector<std::string> words(android::base::Split(reason, ",_-"));
    for (auto &s : knownReasons) {
      std::string blunt;
      for (auto &r : words) {
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
    // to behave and follow our standards.
    static const std::vector<std::pair<const std::string, const std::string>> aliasReasons = {
      {"watchdog", "wdog"},
      {"cold,powerkey", "powerkey"},
      {"kernel_panic", "panic"},
      {"shutdown,thermal", "thermal"},
      {"warm,s3_wakeup", "s3_wakeup"},
      {"hard,hw_reset", "hw_reset"},
      {"bootloader", ""},
    };

    // Either the primary or alias is found _somewhere_ in the reason string.
    for (auto &s : aliasReasons) {
      if (reason.find(s.first) != std::string::npos) {
        ret = s.first;
        break;
      }
      if (s.second.size() && (reason.find(s.second) != std::string::npos)) {
        ret = s.first;
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

  // Check the other reason resources if the reason is still blunt.
  if (isBluntRebootReason(ret)) {
    // Check to see if last klog has some refinement hints.
    std::string content;
    if (!android::base::ReadFileToString("/sys/fs/pstore/console-ramoops-0",
                                         &content)) {
        android::base::ReadFileToString("/sys/fs/pstore/console-ramoops",
                                         &content);
    }

    // The toybox reboot command used directly (unlikely)? But also
    // catches init's response to the Android's more controlled reboot command.
    if (content.rfind("reboot: Power down") != std::string::npos) {
      ret = "shutdown"; // Still too blunt, but more accurate.
      // ToDo: init should record the shutdown reason to kernel messages ala:
      //           init: shutdown system with command 'last_reboot_reason'
      //       so that if pstore has persistence we can get some details
      //       that could be missing in last_reboot_reason_property.
    }

    static const char cmd[] = "reboot: Restarting system with command '";
    size_t pos = content.rfind(cmd);
    if (pos != std::string::npos) {
      pos += strlen(cmd);
      std::string subReason(content.substr(pos));
      pos = subReason.find('\'');
      if (pos != std::string::npos) subReason.erase(pos);
      if (subReason != "") { // Will not land "reboot" as that is too blunt.
        if (isKernelRebootReason(subReason)) {
          ret = "reboot," + subReason; // User space can't talk kernel reasons.
        } else {
          ret = subReason;
        }
      }
    }

    // Check for kernel panics, but allowed to override reboot command.
    if (content.rfind("sysrq: SysRq : Trigger a crash") != std::string::npos) {
      // Can not happen, except on userdebug, during testing/debugging.
      ret = "kernel_panic,sysrq";
    } else if (content.rfind(
        "Unable to handle kernel NULL pointer dereference at virtual address")
               != std::string::npos) {
      ret = "kernel_panic,NULL";
    } else if (content.rfind("Kernel BUG at ") != std::string::npos) {
      ret = "kernel_panic,BUG";
    } else if ((content.rfind("Power held for ") != std::string::npos) ||
        (content.rfind("charger: [") != std::string::npos)) {
      ret = "cold";
    }

    // The following battery test should migrate to a default system health HAL

    // Let us not worry if the reboot command was issued, for the cases of
    // reboot -p, reboot <no reason>, reboot cold, reboot warm and reboot hard.
    // Same for bootloader and ro.boot.bootreasons of this set, but a dead
    // battery could conceivably lead to these, so worthy of override.
    if (isBluntRebootReason(ret)) {
      // Heuristic to determine if shutdown possibly because of a dead battery?
      // Really a hail-mary pass to find it in last klog content ...
      static const int battery_dead_threshold = 2; // percent
      static const char battery[] = "healthd: battery l=";
      pos = content.rfind(battery); // last one
      if (pos != std::string::npos) {
        int level = atoi(content.substr(pos + strlen(battery)).c_str());
        LOG(INFO) << "Battery level at shutdown " << level << "%";
        if (level <= battery_dead_threshold) {
          ret = "shutdown,battery";
        }
      } else { // Most likely
        // Content buffer no longer will have console data. Beware if more
        // checks added below, that depend on parsing console content.
        content = "";

        LOG(DEBUG) << "Can not find last low battery in last console messages";
        android_logcat_context ctx = create_android_logcat();
        FILE *fp = android_logcat_popen(&ctx, "logcat -b kernel -v brief -d");
        if (fp != nullptr) {
          android::base::ReadFdToString(fileno(fp), &content);
        }
        android_logcat_pclose(&ctx, fp);
        android_logcat_destroy(&ctx);
        static const char logcat_battery[] = "W/healthd (    0): battery l=";
        const char* match = logcat_battery;

        if (content == "") {
          // Service logd.klog not running, go to smaller buffer in the kernel.
          int rc = klogctl(KLOG_SIZE_BUFFER, nullptr, 0);
          if (rc > 0) {
            ssize_t len = rc + 1024; // 1K Margin should it grow between calls.
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

        pos = content.find(match); // The first one it finds.
        if (pos != std::string::npos) {
          pos += strlen(match);
          int level = atoi(content.substr(pos).c_str());
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

      // String is either "reboot,<reason>" or "shutdown,<reason>".
      // We will set if default reasons, only override with detail if thermal.
      if ((android::base::StartsWith(content, ret.c_str()) && (content[ret.length()] == ',')) ||
          !isBluntRebootReason(content)) {
        // Ok, we want it, let's squash it if secondReason is known.
        pos = content.find(',');
        if (pos != std::string::npos) {
          ++pos;
          std::string secondReason(content.substr(pos));
          ret = isKnownRebootReason(secondReason) ? secondReason : content;
        } else {
          ret = content;
        }
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
      while (reason[0] == ',') {
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
    LOG(INFO) << "Canonical boot reason: " << "reboot,factory_reset";
    SetProperty(system_reboot_reason_property, "reboot,factory_reset");
    if (GetProperty(bootloader_reboot_reason_property) == "") {
      SetProperty(bootloader_reboot_reason_property, "reboot,factory_reset");
    }
  } else if (build_date != record.second) {
    boot_complete_prefix = "ota_" + boot_complete_prefix;
    boot_event_store.AddBootEventWithValue(kBuildDateKey, build_date);
    LOG(INFO) << "Canonical boot reason: " << "reboot,ota";
    SetProperty(system_reboot_reason_property, "reboot,ota");
    if (GetProperty(bootloader_reboot_reason_property) == "") {
      SetProperty(bootloader_reboot_reason_property, "reboot,ota");
    }
  }

  return boot_complete_prefix;
}

// Records the value of a given ro.boottime.init property in milliseconds.
void RecordInitBootTimeProp(
    BootEventRecordStore* boot_event_store, const char* property) {
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

// Records several metrics related to the time it takes to boot the device,
// including disambiguating boot time on encrypted or non-encrypted devices.
void RecordBootComplete() {
  BootEventRecordStore boot_event_store;
  BootEventRecordStore::BootEventRecord record;

  auto time_since_epoch = android::base::boot_clock::now().time_since_epoch();
  auto uptime = std::chrono::duration_cast<std::chrono::seconds>(time_since_epoch);
  time_t current_time_utc = time(nullptr);

  if (boot_event_store.GetBootEvent("last_boot_time_utc", &record)) {
    time_t last_boot_time_utc = record.second;
    time_t time_since_last_boot = difftime(current_time_utc,
                                           last_boot_time_utc);
    boot_event_store.AddBootEventWithValue("time_since_last_boot",
                                           time_since_last_boot);
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
    boot_event_store.AddBootEventWithValue("boot_decryption_complete", uptime.count());

    // Subtract the decryption time to normalize the boot cycle timing.
    std::chrono::seconds boot_complete = std::chrono::seconds(uptime.count() - record.second);
    boot_event_store.AddBootEventWithValue(boot_complete_prefix + "_post_decrypt",
                                           boot_complete.count());
  } else {
      boot_event_store.AddBootEventWithValue(boot_complete_prefix + "_no_encryption",
                                             uptime.count());
  }

  // Record the total time from device startup to boot complete, regardless of
  // encryption state.
  boot_event_store.AddBootEventWithValue(boot_complete_prefix, uptime.count());

  RecordInitBootTimeProp(&boot_event_store, "ro.boottime.init");
  RecordInitBootTimeProp(&boot_event_store, "ro.boottime.init.selinux");
  RecordInitBootTimeProp(&boot_event_store, "ro.boottime.init.cold_boot_wait");

  const BootloaderTimingMap bootloader_timings = GetBootLoaderTimings();
  RecordBootloaderTimings(&boot_event_store, bootloader_timings);

  auto uptime_ms = std::chrono::duration_cast<std::chrono::milliseconds>(time_since_epoch);
  RecordAbsoluteBootTime(&boot_event_store, bootloader_timings, uptime_ms);
}

// Records the boot_reason metric by querying the ro.boot.bootreason system
// property.
void RecordBootReason() {
  const std::string reason(GetProperty(bootloader_reboot_reason_property));
  android::metricslogger::LogMultiAction(android::metricslogger::ACTION_BOOT,
                                         android::metricslogger::FIELD_PLATFORM_REASON,
                                         reason);

  // Log the raw bootloader_boot_reason property value.
  int32_t boot_reason = BootReasonStrToEnum(reason);
  BootEventRecordStore boot_event_store;
  boot_event_store.AddBootEventWithValue("boot_reason", boot_reason);

  // Log the scrubbed system_boot_reason.
  const std::string system_reason(BootReasonStrToReason(reason));
  int32_t system_boot_reason = BootReasonStrToEnum(system_reason);
  boot_event_store.AddBootEventWithValue("system_boot_reason", system_boot_reason);

  // Record the scrubbed system_boot_reason to the property
  SetProperty(system_reboot_reason_property, system_reason);
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
    android::metricslogger::LogHistogram(
        "factory_reset_current_time_failure", std::abs(current_time_utc));

    // Logging via BootEventRecordStore to see if using android::metricslogger::LogHistogram
    // is losing records somehow.
    boot_event_store.AddBootEventWithValue(
        "factory_reset_current_time_failure", std::abs(current_time_utc));
    return;
  } else {
    android::metricslogger::LogHistogram("factory_reset_current_time", current_time_utc);

    // Logging via BootEventRecordStore to see if using android::metricslogger::LogHistogram
    // is losing records somehow.
    boot_event_store.AddBootEventWithValue(
        "factory_reset_current_time", current_time_utc);
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
  boot_event_store.AddBootEventWithValue(
      "factory_reset_record_value", factory_reset_utc);

  time_t time_since_factory_reset = difftime(current_time_utc,
                                             factory_reset_utc);
  boot_event_store.AddBootEventWithValue("time_since_factory_reset",
                                         time_since_factory_reset);
}

}  // namespace

int main(int argc, char **argv) {
  android::base::InitLogging(argv);

  const std::string cmd_line = GetCommandLine(argc, argv);
  LOG(INFO) << "Service started: " << cmd_line;

  int option_index = 0;
  static const char value_str[] = "value";
  static const char boot_complete_str[] = "record_boot_complete";
  static const char boot_reason_str[] = "record_boot_reason";
  static const char factory_reset_str[] = "record_time_since_factory_reset";
  static const struct option long_options[] = {
    { "help",            no_argument,       NULL,   'h' },
    { "log",             no_argument,       NULL,   'l' },
    { "print",           no_argument,       NULL,   'p' },
    { "record",          required_argument, NULL,   'r' },
    { value_str,         required_argument, NULL,   0 },
    { boot_complete_str, no_argument,       NULL,   0 },
    { boot_reason_str,   no_argument,       NULL,   0 },
    { factory_reset_str, no_argument,       NULL,   0 },
    { NULL,              0,                 NULL,   0 }
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

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
#include <cmath>
#include <cstddef>
#include <cstdio>
#include <ctime>
#include <map>
#include <memory>
#include <string>
#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <cutils/properties.h>
#include <log/log.h>
#include "boot_event_record_store.h"
#include "event_log_list_builder.h"
#include "histogram_logger.h"
#include "uptime_parser.h"

namespace {

// Scans the boot event record store for record files and logs each boot event
// via EventLog.
void LogBootEvents() {
  BootEventRecordStore boot_event_store;

  auto events = boot_event_store.GetAllBootEvents();
  for (auto i = events.cbegin(); i != events.cend(); ++i) {
    bootstat::LogHistogram(i->first, i->second);
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
          "  -h, --help            Show this help\n"
          "  -l, --log             Log all metrics to logstorage\n"
          "  -p, --print           Dump the boot event records to the console\n"
          "  -r, --record          Record the timestamp of a named boot event\n"
          "  --record_boot_reason  Record the reason why the device booted\n"
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
  if (!android::base::ParseInt(build_date_str.c_str(), &build_date)) {
    return std::string();
  }

  BootEventRecordStore boot_event_store;
  BootEventRecordStore::BootEventRecord record;
  if (!boot_event_store.GetBootEvent(kBuildDateKey, &record) ||
      build_date != record.second) {
    boot_complete_prefix = "ota_" + boot_complete_prefix;
    boot_event_store.AddBootEventWithValue(kBuildDateKey, build_date);
  }

  return boot_complete_prefix;
}

// Records several metrics related to the time it takes to boot the device,
// including disambiguating boot time on encrypted or non-encrypted devices.
void RecordBootComplete() {
  BootEventRecordStore boot_event_store;
  BootEventRecordStore::BootEventRecord record;

  time_t uptime = bootstat::ParseUptime();
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
    boot_event_store.AddBootEventWithValue("boot_decryption_complete", uptime);

    // Subtract the decryption time to normalize the boot cycle timing.
    time_t boot_complete = uptime - record.second;
    boot_event_store.AddBootEventWithValue(boot_complete_prefix + "_post_decrypt",
                                           boot_complete);


  } else {
    boot_event_store.AddBootEventWithValue(boot_complete_prefix + "_no_encryption",
                                           uptime);
  }

  // Record the total time from device startup to boot complete, regardless of
  // encryption state.
  boot_event_store.AddBootEventWithValue(boot_complete_prefix, uptime);
}

// Records the boot_reason metric by querying the ro.boot.bootreason system
// property.
void RecordBootReason() {
  int32_t boot_reason = BootReasonStrToEnum(GetProperty("ro.boot.bootreason"));
  BootEventRecordStore boot_event_store;
  boot_event_store.AddBootEventWithValue("boot_reason", boot_reason);
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
    bootstat::LogHistogram(
        "factory_reset_current_time_failure", std::abs(current_time_utc));

    // Logging via BootEventRecordStore to see if using bootstat::LogHistogram
    // is losing records somehow.
    boot_event_store.AddBootEventWithValue(
        "factory_reset_current_time_failure", std::abs(current_time_utc));
    return;
  } else {
    bootstat::LogHistogram("factory_reset_current_time", current_time_utc);

    // Logging via BootEventRecordStore to see if using bootstat::LogHistogram
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
  bootstat::LogHistogram("factory_reset_record_value", factory_reset_utc);

  // Logging via BootEventRecordStore to see if using bootstat::LogHistogram
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
  static const char boot_complete_str[] = "record_boot_complete";
  static const char boot_reason_str[] = "record_boot_reason";
  static const char factory_reset_str[] = "record_time_since_factory_reset";
  static const struct option long_options[] = {
    { "help",            no_argument,       NULL,   'h' },
    { "log",             no_argument,       NULL,   'l' },
    { "print",           no_argument,       NULL,   'p' },
    { "record",          required_argument, NULL,   'r' },
    { boot_complete_str, no_argument,       NULL,   0 },
    { boot_reason_str,   no_argument,       NULL,   0 },
    { factory_reset_str, no_argument,       NULL,   0 },
    { NULL,              0,                 NULL,   0 }
  };

  int opt = 0;
  while ((opt = getopt_long(argc, argv, "hlpr:", long_options, &option_index)) != -1) {
    switch (opt) {
      // This case handles long options which have no single-character mapping.
      case 0: {
        const std::string option_name = long_options[option_index].name;
        if (option_name == boot_complete_str) {
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
        const char* event = optarg;

        BootEventRecordStore boot_event_store;
        boot_event_store.AddBootEvent(event);
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

  return 0;
}

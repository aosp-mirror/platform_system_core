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
#include <cstddef>
#include <cstdio>
#include <map>
#include <memory>
#include <string>
#include <android-base/logging.h>
#include <cutils/properties.h>
#include <log/log.h>
#include "boot_event_record_store.h"
#include "event_log_list_builder.h"

namespace {

// Builds an EventLog buffer named |event| containing |data| and writes
// the log into the Tron histogram logs.
void LogBootEvent(const std::string& event, int32_t data) {
  LOG(INFO) << "Logging boot metric: " << event << " " << data;

  EventLogListBuilder log_builder;
  log_builder.Append(event);
  log_builder.Append(data);

  std::unique_ptr<uint8_t[]> log;
  size_t size;
  log_builder.Release(&log, &size);

  android_bWriteLog(HISTOGRAM_LOG_TAG, log.get(), size);
}

// Scans the boot event record store for record files and logs each boot event
// via EventLog.
void LogBootEvents() {
  BootEventRecordStore boot_event_store;

  auto events = boot_event_store.GetAllBootEvents();
  for (auto i = events.cbegin(); i != events.cend(); ++i) {
    LogBootEvent(i->first, i->second);
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
          "  --record_boot_reason  Record the reason why the device booted\n");
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

// A mapping from boot reason string, as read from the ro.boot.bootreason
// system property, to a unique integer ID. Viewers of log data dashboards for
// the boot_reason metric may refer to this mapping to discern the histogram
// values.
const std::map<std::string, int> kBootReasonMap = {
  {"normal", 0},
  {"recovery", 1},
  {"reboot", 2},
  {"PowerKey", 3},
  {"hard_reset", 4},
  {"kernel_panic", 5},
  {"rpm_err", 6},
  {"hw_reset", 7},
  {"tz_err", 8},
  {"adsp_err", 9},
  {"modem_err", 10},
  {"mba_err", 11},
  {"Watchdog", 12},
  {"Panic", 13},
};

// Converts a string value representing the reason the system booted to an
// integer representation. This is necessary for logging the boot_reason metric
// via Tron, which does not accept non-integer buckets in histograms.
int32_t BootReasonStrToEnum(const std::string& boot_reason) {
  static const int32_t kUnknownBootReason = -1;

  auto mapping = kBootReasonMap.find(boot_reason);
  if (mapping != kBootReasonMap.end()) {
    return mapping->second;
  }

  LOG(INFO) << "Unknown boot reason: " << boot_reason;
  return kUnknownBootReason;
}

// Records the boot_reason metric by querying the ro.boot.bootreason system
// property.
void RecordBootReason() {
  int32_t boot_reason = BootReasonStrToEnum(GetProperty("ro.boot.bootreason"));
  BootEventRecordStore boot_event_store;
  boot_event_store.AddBootEventWithValue("boot_reason", boot_reason);
}

}  // namespace

int main(int argc, char **argv) {
  android::base::InitLogging(argv);

  const std::string cmd_line = GetCommandLine(argc, argv);
  LOG(INFO) << "Service started: " << cmd_line;

  int option_index = 0;
  static const char boot_reason_str[] = "record_boot_reason";
  static const struct option long_options[] = {
    { "help",            no_argument,       NULL,   'h' },
    { "log",             no_argument,       NULL,   'l' },
    { "print",           no_argument,       NULL,   'p' },
    { "record",          required_argument, NULL,   'r' },
    { boot_reason_str,   no_argument,       NULL,   0 },
    { NULL,              0,                 NULL,   0 }
  };

  int opt = 0;
  while ((opt = getopt_long(argc, argv, "hlpr:", long_options, &option_index)) != -1) {
    switch (opt) {
      // This case handles long options which have no single-character mapping.
      case 0: {
        const std::string option_name = long_options[option_index].name;
        if (option_name == boot_reason_str) {
          RecordBootReason();
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

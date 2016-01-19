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

//#define LOG_TAG "bootstat"

#include <unistd.h>
#include <cstddef>
#include <cstdio>
#include <memory>
#include <string>
#include <base/logging.h>
#include <log/log.h>
#include "boot_event_record_store.h"
#include "event_log_list_builder.h"

namespace {

// Builds an EventLog buffer named |event| containing |data| and writes
// the log into the Tron histogram logs.
void LogBootEvent(const std::string& event, int32_t data) {
  LOG(INFO) << "Logging boot time: " << event << " " << data;

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
          "  -d              Dump the boot event records to the console.\n"
          "  -h              Show this help.\n"
          "  -l              Log all metrics to logstorage.\n"
          "  -r              Record the timestamp of a named boot event.\n");
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

}  // namespace

int main(int argc, char **argv) {
  android::base::InitLogging(argv);

  const std::string cmd_line = GetCommandLine(argc, argv);
  LOG(INFO) << "Service started: " << cmd_line;

  int opt = 0;
  while ((opt = getopt(argc, argv, "hlpr:")) != -1) {
    switch (opt) {
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

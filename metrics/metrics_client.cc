// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstdio>
#include <cstdlib>

#include "metrics_library.h"

// Usage:  metrics_client [-ab] metric_name metric_value
int main(int argc, char** argv) {
  bool send_to_autotest = false;
  bool send_to_chrome = true;
  bool secs_to_msecs = false;
  int metric_name_index = 1;
  int metric_value_index = 2;
  bool print_usage = false;

  if (argc >= 3) {
    // Parse arguments
    int flag;
    while ((flag = getopt(argc, argv, "abt")) != -1) {
      switch (flag) {
        case 'a':
          send_to_autotest = true;
          send_to_chrome = false;
          break;
        case 'b':
          send_to_chrome = true;
          send_to_autotest = true;
          break;
        case 't':
          secs_to_msecs = true;
          break;
        default:
          print_usage = true;
          break;
      }
    }
    metric_name_index = optind;
    metric_value_index = optind + 1;
  } else {
    print_usage = true;
  }

  // Metrics value should be the last argument passed
  if ((metric_value_index + 1) != argc) {
    print_usage = true;
  }

  if (print_usage) {
    fprintf(stderr,
            "Usage:  metrics_client [-abt] name value\n"
            "\n"
            "  default: send metric with integer value to chrome only\n"
            "  -a: send metric to autotest only\n"
            "  -b: send metric to both chrome and autotest\n"
            "  -t: convert value from float seconds to int milliseconds\n");
    return 1;
  }

  const char* name = argv[metric_name_index];
  int value;
  if (secs_to_msecs) {
    float secs = strtof(argv[metric_value_index], NULL);
    value = static_cast<int>(secs * 1000.0f);
  } else {
    value = atoi(argv[metric_value_index]);
  }

  // Send metrics
  if (send_to_autotest) {
    MetricsLibrary::SendToAutotest(name, value);
  }
  if (send_to_chrome) {
    MetricsLibrary::SendToChrome(name, value);
  }
  return 0;
}

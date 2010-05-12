// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstdio>
#include <cstdlib>

#include "metrics_library.h"

int main(int argc, char** argv) {
  bool send_to_autotest = false;
  bool send_to_chrome = true;
  bool send_enum = false;
  bool secs_to_msecs = false;
  int name_index = 1;
  bool print_usage = false;

  if (argc >= 3) {
    // Parse arguments
    int flag;
    while ((flag = getopt(argc, argv, "abet")) != -1) {
      switch (flag) {
        case 'a':
          send_to_autotest = true;
          send_to_chrome = false;
          break;
        case 'b':
          send_to_chrome = true;
          send_to_autotest = true;
          break;
        case 'e':
          send_enum = true;
          break;
        case 't':
          secs_to_msecs = true;
          break;
        default:
          print_usage = true;
          break;
      }
    }
    name_index = optind;
  } else {
    print_usage = true;
  }

  int num_args = send_enum ? 3 : 5;
  if ((name_index + num_args) != argc ||
      (send_enum && secs_to_msecs)) {
    print_usage = true;
  }

  if (print_usage) {
    fprintf(stderr,
            "Usage:  metrics_client [-ab] [-t] name sample min max nbuckets\n"
            "        metrics_client [-ab] -e   name sample max\n"
            "\n"
            "  default: send metric with integer values to Chrome only\n"
            "           |min| > 0, |min| <= sample < |max|\n"
            "  -a: send metric (name/sample) to Autotest only\n"
            "  -b: send metric to both Chrome and Autotest\n"
            "  -e: send linear/enumeration histogram data\n"
            "  -t: convert sample from double seconds to int milliseconds\n");
    return 1;
  }

  const char* name = argv[name_index];
  int sample;
  if (secs_to_msecs) {
    sample = static_cast<int>(atof(argv[name_index + 1]) * 1000.0);
  } else {
    sample = atoi(argv[name_index + 1]);
  }

  // Send metrics
  if (send_to_autotest) {
    MetricsLibrary::SendToAutotest(name, sample);
  }

  if (send_to_chrome) {
    MetricsLibrary metrics_lib;
    metrics_lib.Init();
    if (send_enum) {
      int max = atoi(argv[name_index + 2]);
      metrics_lib.SendEnumToUMA(name, sample, max);
    } else {
      int min = atoi(argv[name_index + 2]);
      int max = atoi(argv[name_index + 3]);
      int nbuckets = atoi(argv[name_index + 4]);
      metrics_lib.SendToUMA(name, sample, min, max, nbuckets);
    }
  }
  return 0;
}

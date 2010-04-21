// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstdio>
#include <cstdlib>

#include "metrics_library.h"

int main(int argc, char** argv) {
  bool send_to_autotest = false;
  bool send_to_chrome = true;
  bool secs_to_msecs = false;
  int name_index = 1;
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
    name_index = optind;
  } else {
    print_usage = true;
  }

  if ((name_index + 5) != argc) {
    print_usage = true;
  }

  if (print_usage) {
    fprintf(stderr,
            "Usage:  metrics_client [-abt] name sample min max nbuckets\n"
            "\n"
            "  default: send metric with integer values to Chrome only\n"
            "  -a: send metric to autotest only (min/max/nbuckets ignored)\n"
            "  -b: send metric to both chrome and autotest\n"
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
  int min = atoi(argv[name_index + 2]);
  int max = atoi(argv[name_index + 3]);
  int nbuckets = atoi(argv[name_index + 4]);

  // Send metrics
  if (send_to_autotest) {
    MetricsLibrary::SendToAutotest(name, sample);
  }
  if (send_to_chrome) {
    MetricsLibrary::SendToChrome(name, sample, min, max, nbuckets);
  }
  return 0;
}

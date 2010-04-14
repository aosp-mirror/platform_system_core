// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <errno.h>
#include <sys/file.h>
#include <string.h>
#include <stdio.h>

#include <cstdlib>
#include <iostream>

#include "metrics_library.h"

using namespace std;

// Usage:  metrics_client [-ab] metric_name metric_value
int main(int argc, char** argv) {
  bool send_to_autotest = false;
  bool send_to_chrome = true;
  int metric_name_index = 1;
  int metric_value_index = 2;
  bool print_usage = false;

  if (argc >= 3) {
    // Parse arguments
    int flag;
    while ((flag = getopt(argc, argv, "ab")) != -1) {
      switch (flag) {
        case 'a':
          send_to_autotest = true;
          send_to_chrome = false;
          break;
        case 'b':
          send_to_chrome = true;
          send_to_autotest = true;
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
    cerr << "Usage:  metrics_client [-ab] name value" << endl;
    cerr << endl;
    cerr << "  default: send metric to chrome only" << endl;
    cerr << "  -a: send metric to autotest only" << endl;
    cerr << "  -b: send metric to both chrome and autotest" << endl;
    return 1;
  }

  // Send metrics
  if (send_to_autotest) {
    MetricsLibrary::SendToAutotest(argv[metric_name_index],
                                   argv[metric_value_index]);
  }
  if (send_to_chrome) {
    MetricsLibrary::SendToChrome(argv[metric_name_index],
                                 argv[metric_value_index]);
  }
  return 0;
}

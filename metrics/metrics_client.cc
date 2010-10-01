// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstdio>
#include <cstdlib>

#include "metrics_library.h"

void ShowUsage() {
  fprintf(stderr,
          "Usage:  metrics_client [-ab] [-t] name sample min max nbuckets\n"
          "        metrics_client [-ab] -e   name sample max\n"
          "        metrics_client [-cg]\n"
          "\n"
          "  default: send metric with integer values to Chrome only\n"
          "           |min| > 0, |min| <= sample < |max|\n"
          "  -a: send metric (name/sample) to Autotest only\n"
          "  -b: send metric to both Chrome and Autotest\n"
          "  -c: return exit status 0 if user consents to stats, 1 otherwise\n"
          "  -e: send linear/enumeration histogram data\n"
          "  -g: return exit status 0 if machine in guest mode, 1 otherwise\n"
          "  -t: convert sample from double seconds to int milliseconds\n");
  exit(1);
}

static int SendStats(char* argv[],
                     int name_index,
                     bool send_enum,
                     bool secs_to_msecs,
                     bool send_to_autotest,
                     bool send_to_chrome) {
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

static int HasConsent() {
  MetricsLibrary metrics_lib;
  metrics_lib.Init();
  return metrics_lib.AreMetricsEnabled() ? 0 : 1;
}

static int IsGuestMode() {
  MetricsLibrary metrics_lib;
  metrics_lib.Init();
  return metrics_lib.IsGuestMode() ? 0 : 1;
}

int main(int argc, char** argv) {
  enum Mode {
    kModeSendStats,
    kModeHasConsent,
    kModeIsGuestMode
  } mode = kModeSendStats;
  bool send_to_autotest = false;
  bool send_to_chrome = true;
  bool send_enum = false;
  bool secs_to_msecs = false;
  bool print_usage = false;

  // Parse arguments
  int flag;
  while ((flag = getopt(argc, argv, "abcegt")) != -1) {
    switch (flag) {
      case 'a':
        mode = kModeSendStats;
        send_to_autotest = true;
        send_to_chrome = false;
        break;
      case 'b':
        mode = kModeSendStats;
        send_to_chrome = true;
        send_to_autotest = true;
        break;
      case 'c':
        mode = kModeHasConsent;
        break;
      case 'e':
        send_enum = true;
        break;
      case 'g':
        mode = kModeIsGuestMode;
        break;
      case 't':
        secs_to_msecs = true;
        break;
      default:
        print_usage = true;
        break;
    }
  }
  int name_index = optind;

  int expected_args = 0;
  if (mode == kModeSendStats)
    expected_args = send_enum ? 3 : 5;

  if ((name_index + expected_args) != argc) {
    ShowUsage();
  }

  switch(mode) {
    case kModeSendStats:
      if (send_enum && secs_to_msecs) {
        ShowUsage();
      }
      return SendStats(argv,
                       name_index,
                       send_enum,
                       secs_to_msecs,
                       send_to_autotest,
                       send_to_chrome);
    case kModeHasConsent:
      return HasConsent();
    case kModeIsGuestMode:
      return IsGuestMode();
    default:
      ShowUsage();
      return 0;
  }
}

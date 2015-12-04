/*
 * Copyright (C) 2015 The Android Open Source Project
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

#include <cstdio>
#include <cstdlib>

#include "constants.h"
#include "metrics/metrics_library.h"

enum Mode {
    kModeDumpHistograms,
    kModeSendSample,
    kModeSendEnumSample,
    kModeSendSparseSample,
    kModeSendCrosEvent,
    kModeHasConsent,
    kModeIsGuestMode,
};

void ShowUsage() {
  fprintf(stderr,
          "Usage:  metrics_client [-t] name sample min max nbuckets\n"
          "        metrics_client -e   name sample max\n"
          "        metrics_client -s   name sample\n"
          "        metrics_client -v   event\n"
          "        metrics_client [-cdg]\n"
          "\n"
          "  default: send metric with integer values \n"
          "           |min| > 0, |min| <= sample < |max|\n"
          "  -c: return exit status 0 if user consents to stats, 1 otherwise,\n"
          "      in guest mode always return 1\n"
          "  -d: dump the histograms recorded by metricsd to stdout\n"
          "  -e: send linear/enumeration histogram data\n"
          "  -g: return exit status 0 if machine in guest mode, 1 otherwise\n"
          "  -s: send a sparse histogram sample\n"
          "  -t: convert sample from double seconds to int milliseconds\n"
          "  -v: send a Platform.CrOSEvent enum histogram sample\n");
  exit(1);
}

static int ParseInt(const char *arg) {
  char *endptr;
  int value = strtol(arg, &endptr, 0);
  if (*endptr != '\0') {
    fprintf(stderr, "metrics client: bad integer \"%s\"\n", arg);
    ShowUsage();
  }
  return value;
}

static double ParseDouble(const char *arg) {
  char *endptr;
  double value = strtod(arg, &endptr);
  if (*endptr != '\0') {
    fprintf(stderr, "metrics client: bad double \"%s\"\n", arg);
    ShowUsage();
  }
  return value;
}

static int DumpHistograms() {
  MetricsLibrary metrics_lib;
  metrics_lib.Init();

  std::string dump;
  if (!metrics_lib.GetHistogramsDump(&dump)) {
    printf("Failed to dump the histograms.");
    return 1;
  }

  printf("%s\n", dump.c_str());
  return 0;
}

static int SendStats(char* argv[],
                     int name_index,
                     enum Mode mode,
                     bool secs_to_msecs) {
  const char* name = argv[name_index];
  int sample;
  if (secs_to_msecs) {
    sample = static_cast<int>(ParseDouble(argv[name_index + 1]) * 1000.0);
  } else {
    sample = ParseInt(argv[name_index + 1]);
  }

  MetricsLibrary metrics_lib;
  metrics_lib.Init();
  if (mode == kModeSendSparseSample) {
    metrics_lib.SendSparseToUMA(name, sample);
  } else if (mode == kModeSendEnumSample) {
    int max = ParseInt(argv[name_index + 2]);
    metrics_lib.SendEnumToUMA(name, sample, max);
  } else {
    int min = ParseInt(argv[name_index + 2]);
    int max = ParseInt(argv[name_index + 3]);
    int nbuckets = ParseInt(argv[name_index + 4]);
    metrics_lib.SendToUMA(name, sample, min, max, nbuckets);
  }
  return 0;
}

static int SendCrosEvent(char* argv[], int action_index) {
  const char* event = argv[action_index];
  bool result;
  MetricsLibrary metrics_lib;
  metrics_lib.Init();
  result = metrics_lib.SendCrosEventToUMA(event);
  if (!result) {
    fprintf(stderr, "metrics_client: could not send event %s\n", event);
    return 1;
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
  enum Mode mode = kModeSendSample;
  bool secs_to_msecs = false;

  // Parse arguments
  int flag;
  while ((flag = getopt(argc, argv, "abcdegstv")) != -1) {
    switch (flag) {
      case 'c':
        mode = kModeHasConsent;
        break;
      case 'd':
        mode = kModeDumpHistograms;
        break;
      case 'e':
        mode = kModeSendEnumSample;
        break;
      case 'g':
        mode = kModeIsGuestMode;
        break;
      case 's':
        mode = kModeSendSparseSample;
        break;
      case 't':
        secs_to_msecs = true;
        break;
      case 'v':
        mode = kModeSendCrosEvent;
        break;
      default:
        ShowUsage();
        break;
    }
  }
  int arg_index = optind;

  int expected_args = 0;
  if (mode == kModeSendSample)
    expected_args = 5;
  else if (mode == kModeSendEnumSample)
    expected_args = 3;
  else if (mode == kModeSendSparseSample)
    expected_args = 2;
  else if (mode == kModeSendCrosEvent)
    expected_args = 1;

  if ((arg_index + expected_args) != argc) {
    ShowUsage();
  }

  switch (mode) {
    case kModeDumpHistograms:
      return DumpHistograms();
    case kModeSendSample:
    case kModeSendEnumSample:
    case kModeSendSparseSample:
      if ((mode != kModeSendSample) && secs_to_msecs) {
        ShowUsage();
      }
      return SendStats(argv,
                       arg_index,
                       mode,
                       secs_to_msecs);
    case kModeSendCrosEvent:
      return SendCrosEvent(argv, arg_index);
    case kModeHasConsent:
      return HasConsent();
    case kModeIsGuestMode:
      return IsGuestMode();
    default:
      ShowUsage();
      return 0;
  }
}

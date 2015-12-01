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

#include "metrics/metrics_library.h"

#include <base/logging.h>
#include <base/strings/stringprintf.h>
#include <errno.h>
#include <sys/file.h>
#include <sys/stat.h>

#include <cstdio>
#include <cstring>

#include "constants.h"
#include "serialization/metric_sample.h"
#include "serialization/serialization_utils.h"

static const char kCrosEventHistogramName[] = "Platform.CrOSEvent";
static const int kCrosEventHistogramMax = 100;

/* Add new cros events here.
 *
 * The index of the event is sent in the message, so please do not
 * reorder the names.
 */
static const char *kCrosEventNames[] = {
  "ModemManagerCommandSendFailure",  // 0
  "HwWatchdogReboot",  // 1
  "Cras.NoCodecsFoundAtBoot",  // 2
  "Chaps.DatabaseCorrupted",  // 3
  "Chaps.DatabaseRepairFailure",  // 4
  "Chaps.DatabaseCreateFailure",  // 5
  "Attestation.OriginSpecificExhausted",  // 6
  "SpringPowerSupply.Original.High",  // 7
  "SpringPowerSupply.Other.High",  // 8
  "SpringPowerSupply.Original.Low",  // 9
  "SpringPowerSupply.ChargerIdle",  // 10
  "TPM.NonZeroDictionaryAttackCounter",  // 11
  "TPM.EarlyResetDuringCommand",  // 12
};

MetricsLibrary::MetricsLibrary() {}
MetricsLibrary::~MetricsLibrary() {}

// We take buffer and buffer_size as parameters in order to simplify testing
// of various alignments of the |device_name| with |buffer_size|.
bool MetricsLibrary::IsDeviceMounted(const char* device_name,
                                     const char* mounts_file,
                                     char* buffer,
                                     int buffer_size,
                                     bool* result) {
  if (buffer == nullptr || buffer_size < 1)
    return false;
  int mounts_fd = open(mounts_file, O_RDONLY);
  if (mounts_fd < 0)
    return false;
  // match_offset describes:
  //   -1 -- not beginning of line
  //   0..strlen(device_name)-1 -- this offset in device_name is next to match
  //   strlen(device_name) -- matched full name, just need a space.
  int match_offset = 0;
  bool match = false;
  while (!match) {
    int read_size = read(mounts_fd, buffer, buffer_size);
    if (read_size <= 0) {
      if (errno == -EINTR)
        continue;
      break;
    }
    for (int i = 0; i < read_size; ++i) {
      if (buffer[i] == '\n') {
        match_offset = 0;
        continue;
      }
      if (match_offset < 0) {
        continue;
      }
      if (device_name[match_offset] == '\0') {
        if (buffer[i] == ' ') {
          match = true;
          break;
        }
        match_offset = -1;
        continue;
      }

      if (buffer[i] == device_name[match_offset]) {
        ++match_offset;
      } else {
        match_offset = -1;
      }
    }
  }
  close(mounts_fd);
  *result = match;
  return true;
}

bool MetricsLibrary::IsGuestMode() {
  char buffer[256];
  bool result = false;
  if (!IsDeviceMounted("guestfs",
                       "/proc/mounts",
                       buffer,
                       sizeof(buffer),
                       &result)) {
    return false;
  }
  return result && (access("/var/run/state/logged-in", F_OK) == 0);
}

bool MetricsLibrary::AreMetricsEnabled() {
  static struct stat stat_buffer;
  time_t this_check_time = time(nullptr);
  if (!use_caching_ || this_check_time != cached_enabled_time_) {
    cached_enabled_time_ = this_check_time;
    cached_enabled_ = stat(consent_file_.value().data(), &stat_buffer) >= 0;
  }
  return cached_enabled_;
}

void MetricsLibrary::Init() {
  base::FilePath dir = base::FilePath(metrics::kSharedMetricsDirectory);
  uma_events_file_ = dir.Append(metrics::kMetricsEventsFileName);
  consent_file_ = dir.Append(metrics::kConsentFileName);
  cached_enabled_ = false;
  cached_enabled_time_ = 0;
  use_caching_ = true;
}

void MetricsLibrary::InitWithNoCaching() {
  Init();
  use_caching_ = false;
}

void MetricsLibrary::InitForTest(const base::FilePath& metrics_directory) {
  uma_events_file_ = metrics_directory.Append(metrics::kMetricsEventsFileName);
  consent_file_ = metrics_directory.Append(metrics::kConsentFileName);
  cached_enabled_ = false;
  cached_enabled_time_ = 0;
  use_caching_ = true;
}

bool MetricsLibrary::SendToUMA(const std::string& name,
                               int sample,
                               int min,
                               int max,
                               int nbuckets) {
  return metrics::SerializationUtils::WriteMetricToFile(
      *metrics::MetricSample::HistogramSample(name, sample, min, max, nbuckets)
           .get(),
      uma_events_file_.value());
}

bool MetricsLibrary::SendEnumToUMA(const std::string& name, int sample,
                                   int max) {
  return metrics::SerializationUtils::WriteMetricToFile(
      *metrics::MetricSample::LinearHistogramSample(name, sample, max).get(),
      uma_events_file_.value());
}

bool MetricsLibrary::SendBoolToUMA(const std::string& name, bool sample) {
  return metrics::SerializationUtils::WriteMetricToFile(
      *metrics::MetricSample::LinearHistogramSample(name,
                                                    sample ? 1 : 0, 2).get(),
      uma_events_file_.value());
}

bool MetricsLibrary::SendSparseToUMA(const std::string& name, int sample) {
  return metrics::SerializationUtils::WriteMetricToFile(
      *metrics::MetricSample::SparseHistogramSample(name, sample).get(),
      uma_events_file_.value());
}

bool MetricsLibrary::SendUserActionToUMA(const std::string& action) {
  return metrics::SerializationUtils::WriteMetricToFile(
      *metrics::MetricSample::UserActionSample(action).get(),
      uma_events_file_.value());
}

bool MetricsLibrary::SendCrashToUMA(const char *crash_kind) {
  return metrics::SerializationUtils::WriteMetricToFile(
      *metrics::MetricSample::CrashSample(crash_kind).get(),
      uma_events_file_.value());
}

bool MetricsLibrary::SendCrosEventToUMA(const std::string& event) {
  for (size_t i = 0; i < arraysize(kCrosEventNames); i++) {
    if (strcmp(event.c_str(), kCrosEventNames[i]) == 0) {
      return SendEnumToUMA(kCrosEventHistogramName, i, kCrosEventHistogramMax);
    }
  }
  return false;
}

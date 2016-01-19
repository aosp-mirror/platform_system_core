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

#ifndef METRICSD_UPLOADER_METRICS_LOG_H_
#define METRICSD_UPLOADER_METRICS_LOG_H_

#include <string>

#include <base/files/file_path.h>
#include <base/macros.h>

#include "uploader/metrics_log_base.h"

// This file defines a set of user experience metrics data recorded by
// the MetricsService. This is the unit of data that is sent to the server.
class SystemProfileSetter;

// This class provides base functionality for logging metrics data.
class MetricsLog : public metrics::MetricsLogBase {
 public:
  // The constructor doesn't set any metadata. The metadata is only set by a
  // SystemProfileSetter.
  MetricsLog();

  // Increment the crash counters in the protobuf.
  // These methods don't have to be thread safe as metrics logs are only
  // accessed by the uploader thread.
  void IncrementUserCrashCount(unsigned int count);
  void IncrementKernelCrashCount(unsigned int count);
  void IncrementUncleanShutdownCount(unsigned int count);

  // Populate the system profile with system information using setter.
  bool PopulateSystemProfile(SystemProfileSetter* setter);

  // Load the log from |path|.
  bool LoadFromFile(const base::FilePath& path);

  // Save this log to |path|.
  bool SaveToFile(const base::FilePath& path);

 private:
  friend class UploadServiceTest;
  FRIEND_TEST(UploadServiceTest, CurrentLogSavedAndResumed);
  FRIEND_TEST(UploadServiceTest, LogContainsAggregatedValues);
  FRIEND_TEST(UploadServiceTest, LogContainsCrashCounts);
  FRIEND_TEST(UploadServiceTest, LogKernelCrash);
  FRIEND_TEST(UploadServiceTest, LogUncleanShutdown);
  FRIEND_TEST(UploadServiceTest, LogUserCrash);
  FRIEND_TEST(UploadServiceTest, UnknownCrashIgnored);

  DISALLOW_COPY_AND_ASSIGN(MetricsLog);
};

#endif  // METRICSD_UPLOADER_METRICS_LOG_H_

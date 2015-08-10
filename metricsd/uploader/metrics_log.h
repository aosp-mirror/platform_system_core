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

#ifndef METRICS_UPLOADER_METRICS_LOG_H_
#define METRICS_UPLOADER_METRICS_LOG_H_

#include <string>

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

  void IncrementUserCrashCount();
  void IncrementKernelCrashCount();
  void IncrementUncleanShutdownCount();

  // Populate the system profile with system information using setter.
  void PopulateSystemProfile(SystemProfileSetter* setter);

 private:
  FRIEND_TEST(UploadServiceTest, LogContainsAggregatedValues);
  FRIEND_TEST(UploadServiceTest, LogKernelCrash);
  FRIEND_TEST(UploadServiceTest, LogUncleanShutdown);
  FRIEND_TEST(UploadServiceTest, LogUserCrash);
  FRIEND_TEST(UploadServiceTest, UnknownCrashIgnored);

  DISALLOW_COPY_AND_ASSIGN(MetricsLog);
};

#endif  // METRICS_UPLOADER_METRICS_LOG_H_

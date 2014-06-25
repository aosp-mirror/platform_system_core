// Copyright 2014 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef METRICS_UPLOADER_METRICS_LOG_H_
#define METRICS_UPLOADER_METRICS_LOG_H_

#include <string>

#include "components/metrics/metrics_log_base.h"

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

// Copyright 2014 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef METRICS_UPLOADER_MOCK_MOCK_SYSTEM_PROFILE_SETTER_H_
#define METRICS_UPLOADER_MOCK_MOCK_SYSTEM_PROFILE_SETTER_H_

#include "uploader/system_profile_setter.h"

namespace metrics {
class ChromeUserMetricsExtension;
}

// Mock profile setter used for testing.
class MockSystemProfileSetter : public SystemProfileSetter {
 public:
  void Populate(metrics::ChromeUserMetricsExtension* profile_proto) OVERRIDE {}
};

#endif  // METRICS_UPLOADER_MOCK_MOCK_SYSTEM_PROFILE_SETTER_H_

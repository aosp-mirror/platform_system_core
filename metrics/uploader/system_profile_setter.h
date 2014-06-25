// Copyright 2014 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef METRICS_UPLOADER_SYSTEM_PROFILE_SETTER_H_
#define METRICS_UPLOADER_SYSTEM_PROFILE_SETTER_H_

namespace metrics {
class ChromeUserMetricsExtension;
}

// Abstract class used to delegate populating SystemProfileProto with system
// information to simplify testing.
class SystemProfileSetter {
 public:
  // Populates the protobuf with system informations.
  virtual void Populate(metrics::ChromeUserMetricsExtension* profile_proto) = 0;
};

#endif  // METRICS_UPLOADER_SYSTEM_PROFILE_SETTER_H_

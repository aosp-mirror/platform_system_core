// Copyright 2014 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "uploader/metrics_log.h"

#include <string>

#include "components/metrics/proto/system_profile.pb.h"
#include "uploader/system_profile_setter.h"

// We use default values for the MetricsLogBase constructor as the setter will
// override them.
MetricsLog::MetricsLog()
    : MetricsLogBase("", 0, metrics::MetricsLogBase::ONGOING_LOG, "") {
}

void MetricsLog::IncrementUserCrashCount() {
  metrics::SystemProfileProto::Stability* stability(
      uma_proto()->mutable_system_profile()->mutable_stability());
  int current = stability->other_user_crash_count();
  stability->set_other_user_crash_count(current + 1);
}

void MetricsLog::IncrementKernelCrashCount() {
  metrics::SystemProfileProto::Stability* stability(
      uma_proto()->mutable_system_profile()->mutable_stability());
  int current = stability->kernel_crash_count();
  stability->set_kernel_crash_count(current + 1);
}

void MetricsLog::IncrementUncleanShutdownCount() {
  metrics::SystemProfileProto::Stability* stability(
      uma_proto()->mutable_system_profile()->mutable_stability());
  int current = stability->unclean_system_shutdown_count();
  stability->set_unclean_system_shutdown_count(current + 1);
}

void MetricsLog::PopulateSystemProfile(SystemProfileSetter* profile_setter) {
  profile_setter->Populate(uma_proto());
}

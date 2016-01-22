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

#include "uploader/metrics_log.h"

#include <string>

#include <base/files/file_util.h>

#include "uploader/proto/system_profile.pb.h"
#include "uploader/system_profile_setter.h"

// We use default values for the MetricsLogBase constructor as the setter will
// override them.
MetricsLog::MetricsLog()
    : MetricsLogBase("", 0, metrics::MetricsLogBase::ONGOING_LOG, "") {
}

bool MetricsLog::LoadFromFile(const base::FilePath& saved_log) {
  std::string encoded_log;
  if (!base::ReadFileToString(saved_log, &encoded_log)) {
    LOG(ERROR) << "Failed to read the metrics log backup from "
               << saved_log.value();
    return false;
  }

  if (!uma_proto()->ParseFromString(encoded_log)) {
    LOG(ERROR) << "Failed to parse log from " << saved_log.value()
               << ", deleting the log";
    base::DeleteFile(saved_log, false);
    uma_proto()->Clear();
    return false;
  }

  VLOG(1) << uma_proto()->histogram_event_size() << " histograms loaded from "
          << saved_log.value();

  return true;
}

bool MetricsLog::SaveToFile(const base::FilePath& path) {
  std::string encoded_log;
  GetEncodedLog(&encoded_log);

  if (static_cast<int>(encoded_log.size()) !=
      base::WriteFile(path, encoded_log.data(), encoded_log.size())) {
    LOG(ERROR) << "Failed to persist the current log to " << path.value();
    return false;
  }
  return true;
}

void MetricsLog::IncrementUserCrashCount(unsigned int count) {
  metrics::SystemProfileProto::Stability* stability(
      uma_proto()->mutable_system_profile()->mutable_stability());
  int current = stability->other_user_crash_count();
  stability->set_other_user_crash_count(current + count);
}

void MetricsLog::IncrementKernelCrashCount(unsigned int count) {
  metrics::SystemProfileProto::Stability* stability(
      uma_proto()->mutable_system_profile()->mutable_stability());
  int current = stability->kernel_crash_count();
  stability->set_kernel_crash_count(current + count);
}

void MetricsLog::IncrementUncleanShutdownCount(unsigned int count) {
  metrics::SystemProfileProto::Stability* stability(
      uma_proto()->mutable_system_profile()->mutable_stability());
  int current = stability->unclean_system_shutdown_count();
  stability->set_unclean_system_shutdown_count(current + count);
}

bool MetricsLog::PopulateSystemProfile(SystemProfileSetter* profile_setter) {
  CHECK(profile_setter);
  return profile_setter->Populate(uma_proto());
}

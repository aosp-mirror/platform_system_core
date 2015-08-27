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

#include "uploader/system_profile_cache.h"

#include <base/files/file_util.h>
#include <base/guid.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <cutils/properties.h>
#include <string>
#include <vector>

#include "constants.h"
#include "persistent_integer.h"
#include "uploader/metrics_log_base.h"
#include "uploader/proto/chrome_user_metrics_extension.pb.h"

namespace {

const char kPersistentSessionIdFilename[] = "Sysinfo.SessionId";

}  // namespace

std::string ChannelToString(
    const metrics::SystemProfileProto_Channel& channel) {
  switch (channel) {
    case metrics::SystemProfileProto::CHANNEL_STABLE:
    return "STABLE";
  case metrics::SystemProfileProto::CHANNEL_DEV:
    return "DEV";
  case metrics::SystemProfileProto::CHANNEL_BETA:
    return "BETA";
  case metrics::SystemProfileProto::CHANNEL_CANARY:
    return "CANARY";
  default:
    return "UNKNOWN";
  }
}

SystemProfileCache::SystemProfileCache()
    : initialized_(false),
    testing_(false),
    config_root_("/"),
    session_id_(new chromeos_metrics::PersistentInteger(
        kPersistentSessionIdFilename)) {
}

SystemProfileCache::SystemProfileCache(bool testing,
                                       const std::string& config_root)
    : initialized_(false),
      testing_(testing),
      config_root_(config_root),
      session_id_(new chromeos_metrics::PersistentInteger(
          kPersistentSessionIdFilename)) {
}

bool SystemProfileCache::Initialize() {
  CHECK(!initialized_)
      << "this should be called only once in the metrics_daemon lifetime.";

  char property_value[PROPERTY_VALUE_MAX];
  property_get(metrics::kBuildTargetIdProperty, property_value, "");
  profile_.build_target_id = std::string(property_value);

  if (profile_.build_target_id.empty()) {
    LOG(ERROR) << "System property " << metrics::kBuildTargetIdProperty
               << " is not set.";
    return false;
  }

  property_get(metrics::kChannelProperty, property_value, "");
  std::string channel(property_value);

  property_get(metrics::kProductVersionProperty, property_value, "");
  profile_.version = std::string(property_value);

  if (channel.empty() || profile_.version.empty()) {
    // If the channel or version is missing, the image is not official.
    // In this case, set the channel to unknown and the version to 0.0.0.0 to
    // avoid polluting the production data.
    channel = "";
    profile_.version = metrics::kDefaultVersion;
  }
  profile_.client_id =
      testing_ ? "client_id_test" :
      GetPersistentGUID(metrics::kMetricsGUIDFilePath);
  profile_.hardware_class = "unknown";
  profile_.channel = ProtoChannelFromString(channel);

  // Increment the session_id everytime we initialize this. If metrics_daemon
  // does not crash, this should correspond to the number of reboots of the
  // system.
  session_id_->Add(1);
  profile_.session_id = static_cast<int32_t>(session_id_->Get());

  initialized_ = true;
  return initialized_;
}

bool SystemProfileCache::InitializeOrCheck() {
  return initialized_ || Initialize();
}

bool SystemProfileCache::Populate(
    metrics::ChromeUserMetricsExtension* metrics_proto) {
  CHECK(metrics_proto);
  if (not InitializeOrCheck()) {
    return false;
  }

  // The client id is hashed before being sent.
  metrics_proto->set_client_id(
      metrics::MetricsLogBase::Hash(profile_.client_id));
  metrics_proto->set_session_id(profile_.session_id);

  // Sets the product id.
  metrics_proto->set_product(9);

  metrics::SystemProfileProto* profile_proto =
      metrics_proto->mutable_system_profile();
  profile_proto->mutable_hardware()->set_hardware_class(
      profile_.hardware_class);
  profile_proto->set_app_version(profile_.version);
  profile_proto->set_channel(profile_.channel);
  metrics::SystemProfileProto_BrilloDeviceData* device_data =
      profile_proto->mutable_brillo();
  device_data->set_build_target_id(profile_.build_target_id);

  return true;
}

std::string SystemProfileCache::GetPersistentGUID(
    const std::string& filename) {
  std::string guid;
  base::FilePath filepath(filename);
  if (!base::ReadFileToString(filepath, &guid)) {
    guid = base::GenerateGUID();
    // If we can't read or write the file, the guid will not be preserved during
    // the next reboot. Crash.
    CHECK(base::WriteFile(filepath, guid.c_str(), guid.size()));
  }
  return guid;
}

metrics::SystemProfileProto_Channel SystemProfileCache::ProtoChannelFromString(
    const std::string& channel) {
  if (channel == "stable") {
    return metrics::SystemProfileProto::CHANNEL_STABLE;
  } else if (channel == "dev") {
    return metrics::SystemProfileProto::CHANNEL_DEV;
  } else if (channel == "beta") {
    return metrics::SystemProfileProto::CHANNEL_BETA;
  } else if (channel == "canary") {
    return metrics::SystemProfileProto::CHANNEL_CANARY;
  }

  DLOG(INFO) << "unknown channel: " << channel;
  return metrics::SystemProfileProto::CHANNEL_UNKNOWN;
}

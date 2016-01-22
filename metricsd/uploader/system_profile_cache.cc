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
#include <brillo/osrelease_reader.h>
#include <string>
#include <update_engine/client.h>
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
      metrics_directory_(metrics::kMetricsdDirectory),
      session_id_(new chromeos_metrics::PersistentInteger(
          kPersistentSessionIdFilename, metrics_directory_)) {}

SystemProfileCache::SystemProfileCache(bool testing,
                                       const base::FilePath& metrics_directory)
    : initialized_(false),
      testing_(testing),
      metrics_directory_(metrics_directory),
      session_id_(new chromeos_metrics::PersistentInteger(
          kPersistentSessionIdFilename, metrics_directory)) {}

bool SystemProfileCache::Initialize() {
  CHECK(!initialized_)
      << "this should be called only once in the metrics_daemon lifetime.";

  brillo::OsReleaseReader reader;
  std::string channel;
  if (testing_) {
    reader.LoadTestingOnly(metrics_directory_);
    channel = "unknown";
  } else {
    reader.Load();
    auto client = update_engine::UpdateEngineClient::CreateInstance();
    if (!client) {
      LOG(ERROR) << "failed to create the update engine client";
      return false;
    }
    if (!client->GetChannel(&channel)) {
      LOG(ERROR) << "failed to read the current channel from update engine.";
      return false;
    }
  }

  if (!reader.GetString(metrics::kProductId, &profile_.product_id)
      || profile_.product_id.empty()) {
    LOG(ERROR) << "product_id is not set.";
    return false;
  }

  if (!reader.GetString(metrics::kProductVersion, &profile_.version)) {
    LOG(ERROR) << "failed to read the product version";
  }

  if (channel.empty() || profile_.version.empty()) {
    // If the channel or version is missing, the image is not official.
    // In this case, set the channel to unknown and the version to 0.0.0.0 to
    // avoid polluting the production data.
    channel = "";
    profile_.version = metrics::kDefaultVersion;
  }
  std::string guid_path = metrics_directory_.Append(
      metrics::kMetricsGUIDFileName).value();
  profile_.client_id = testing_ ?
      "client_id_test" :
      GetPersistentGUID(guid_path);
  profile_.model_manifest_id = "unknown";
  if (!testing_) {
    brillo::KeyValueStore weave_config;
    if (!weave_config.Load(base::FilePath(metrics::kWeaveConfigurationFile))) {
      LOG(ERROR) << "Failed to load the weave configuration file.";
    } else if (!weave_config.GetString(metrics::kModelManifestId,
                                       &profile_.model_manifest_id)) {
      LOG(ERROR) << "The model manifest id (model_id) is undefined in "
                 << metrics::kWeaveConfigurationFile;
    }
  }

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
      profile_.model_manifest_id);
  profile_proto->set_app_version(profile_.version);
  profile_proto->set_channel(profile_.channel);
  metrics::SystemProfileProto_BrilloDeviceData* device_data =
      profile_proto->mutable_brillo();
  device_data->set_product_id(profile_.product_id);

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
  if (channel == "stable-channel") {
    return metrics::SystemProfileProto::CHANNEL_STABLE;
  } else if (channel == "dev-channel") {
    return metrics::SystemProfileProto::CHANNEL_DEV;
  } else if (channel == "beta-channel") {
    return metrics::SystemProfileProto::CHANNEL_BETA;
  } else if (channel == "canary-channel") {
    return metrics::SystemProfileProto::CHANNEL_CANARY;
  }

  DLOG(INFO) << "unknown channel: " << channel;
  return metrics::SystemProfileProto::CHANNEL_UNKNOWN;
}

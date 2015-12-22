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

#ifndef METRICS_UPLOADER_SYSTEM_PROFILE_CACHE_H_
#define METRICS_UPLOADER_SYSTEM_PROFILE_CACHE_H_

#include <stdint.h>

#include <memory>
#include <string>

#include "base/compiler_specific.h"
#include "base/files/file_path.h"
#include "base/gtest_prod_util.h"
#include "persistent_integer.h"
#include "uploader/proto/system_profile.pb.h"
#include "uploader/system_profile_setter.h"

namespace metrics {
class ChromeUserMetricsExtension;
}

struct SystemProfile {
  std::string version;
  std::string model_manifest_id;
  std::string client_id;
  int session_id;
  metrics::SystemProfileProto::Channel channel;
  std::string product_id;
};

// Retrieves general system informations needed by the protobuf for context and
// remembers them to avoid expensive calls.
//
// The cache is populated lazily. The only method needed is Populate.
class SystemProfileCache : public SystemProfileSetter {
 public:
  SystemProfileCache();

  SystemProfileCache(bool testing, const base::FilePath& metrics_directory);

  // Populates the ProfileSystem protobuf with system information.
  bool Populate(metrics::ChromeUserMetricsExtension* metrics_proto) override;

  // Converts a string representation of the channel to a
  // SystemProfileProto_Channel
  static metrics::SystemProfileProto_Channel ProtoChannelFromString(
      const std::string& channel);

  // Gets the persistent GUID and create it if it has not been created yet.
  static std::string GetPersistentGUID(const std::string& filename);

 private:
  friend class UploadServiceTest;
  FRIEND_TEST(UploadServiceTest, ExtractChannelFromDescription);
  FRIEND_TEST(UploadServiceTest, ReadKeyValueFromFile);
  FRIEND_TEST(UploadServiceTest, SessionIdIncrementedAtInitialization);
  FRIEND_TEST(UploadServiceTest, ValuesInConfigFileAreSent);
  FRIEND_TEST(UploadServiceTest, ProductIdMandatory);

  // Fetches all informations and populates |profile_|
  bool Initialize();

  // Initializes |profile_| only if it has not been yet initialized.
  bool InitializeOrCheck();

  bool initialized_;
  bool testing_;
  base::FilePath metrics_directory_;
  std::unique_ptr<chromeos_metrics::PersistentInteger> session_id_;
  SystemProfile profile_;
};

#endif  // METRICS_UPLOADER_SYSTEM_PROFILE_CACHE_H_

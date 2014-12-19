// Copyright 2014 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef METRICS_UPLOADER_SYSTEM_PROFILE_CACHE_H_
#define METRICS_UPLOADER_SYSTEM_PROFILE_CACHE_H_

#include <stdint.h>

#include <string>

#include "base/compiler_specific.h"
#include "base/gtest_prod_util.h"
#include "base/memory/scoped_ptr.h"
#include "chromeos/osrelease_reader.h"
#include "components/metrics/proto/system_profile.pb.h"
#include "metrics/persistent_integer.h"
#include "metrics/uploader/system_profile_setter.h"

namespace metrics {
class ChromeUserMetricsExtension;
}

struct SystemProfile {
  std::string os_name;
  std::string os_version;
  metrics::SystemProfileProto::Channel channel;
  std::string app_version;
  std::string hardware_class;
  std::string client_id;
  int32_t session_id;
  int32_t product_id;
};

// Retrieves general system informations needed by the protobuf for context and
// remembers them to avoid expensive calls.
//
// The cache is populated lazily. The only method needed is Populate.
class SystemProfileCache : public SystemProfileSetter {
 public:
  SystemProfileCache();

  SystemProfileCache(bool testing, const std::string& config_root);

  // Populates the ProfileSystem protobuf with system information.
  void Populate(metrics::ChromeUserMetricsExtension* profile_proto) override;

  // Converts a string representation of the channel (|channel|-channel) to a
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

  // Fetches all informations and populates |profile_|
  bool Initialize();

  // Initializes |profile_| only if it has not been yet initialized.
  bool InitializeOrCheck();

  // Gets the hardware ID using crossystem
  bool GetHardwareId(std::string* hwid);

  // Gets the product ID from the GOOGLE_METRICS_PRODUCT_ID field.
  bool GetProductId(int* product_id) const;

  // Generate the formatted chromeos version from the fields in
  // /etc/lsb-release. The format is A.B.C.D where A, B, C and D are positive
  // integer representing:
  // * the chrome milestone
  // * the build number
  // * the branch number
  // * the patch number
  bool GetChromeOSVersion(std::string* version);

  bool initialized_;
  bool testing_;
  std::string config_root_;
  scoped_ptr<chromeos_metrics::PersistentInteger> session_id_;
  SystemProfile profile_;
};

#endif  // METRICS_UPLOADER_SYSTEM_PROFILE_CACHE_H_

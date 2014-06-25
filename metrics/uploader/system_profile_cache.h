// Copyright 2014 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef METRICS_UPLOADER_SYSTEM_PROFILE_CACHE_H_
#define METRICS_UPLOADER_SYSTEM_PROFILE_CACHE_H_

#include <string>

#include "base/basictypes.h"
#include "base/compiler_specific.h"
#include "base/gtest_prod_util.h"
#include "base/memory/scoped_ptr.h"
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
  int32 session_id;
};

// Retrieves general system informations needed by the protobuf for context and
// remembers them to avoid expensive calls.
//
// The cache is populated lazily. The only method needed is Populate.
class SystemProfileCache : public SystemProfileSetter {
 public:
  SystemProfileCache();

  // Populates the ProfileSystem protobuf with system information.
  void Populate(metrics::ChromeUserMetricsExtension* profile_proto) OVERRIDE;

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

  static const char* kPersistentGUIDFile;
  static const char* kPersistentSessionIdFilename;

  // Fetches all informations and populates |profile_|
  bool Initialize();

  // Initializes |profile_| only if it has not been yet initialized.
  bool InitializeOrCheck();

  // Gets the hardware ID using crossystem
  bool GetHardwareId(std::string* hwid);

  bool initialized_;
  bool is_testing_;
  scoped_ptr<chromeos_metrics::PersistentInteger> session_id_;
  SystemProfile profile_;
};

#endif  // METRICS_UPLOADER_SYSTEM_PROFILE_CACHE_H_

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

#ifndef METRICS_UPLOADER_MOCK_MOCK_SYSTEM_PROFILE_SETTER_H_
#define METRICS_UPLOADER_MOCK_MOCK_SYSTEM_PROFILE_SETTER_H_

#include "uploader/system_profile_setter.h"

namespace metrics {
class ChromeUserMetricsExtension;
}

// Mock profile setter used for testing.
class MockSystemProfileSetter : public SystemProfileSetter {
 public:
  bool Populate(metrics::ChromeUserMetricsExtension* profile_proto) override {
    return true;
  }
};

#endif  // METRICS_UPLOADER_MOCK_MOCK_SYSTEM_PROFILE_SETTER_H_

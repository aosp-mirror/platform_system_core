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

#ifndef METRICS_METRICS_LIBRARY_MOCK_H_
#define METRICS_METRICS_LIBRARY_MOCK_H_

#include <string>

#include "metrics/metrics_library.h"

#include <gmock/gmock.h>

class MetricsLibraryMock : public MetricsLibraryInterface {
 public:
  bool metrics_enabled_ = true;

  MOCK_METHOD0(Init, void());
  MOCK_METHOD5(SendToUMA, bool(const std::string& name, int sample,
                               int min, int max, int nbuckets));
  MOCK_METHOD3(SendEnumToUMA, bool(const std::string& name, int sample,
                                   int max));
  MOCK_METHOD2(SendBoolToUMA, bool(const std::string& name, bool sample));
  MOCK_METHOD2(SendSparseToUMA, bool(const std::string& name, int sample));

  bool AreMetricsEnabled() override {return metrics_enabled_;};
};

#endif  // METRICS_METRICS_LIBRARY_MOCK_H_

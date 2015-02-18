// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

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
  MOCK_METHOD2(SendSparseToUMA, bool(const std::string& name, int sample));
  MOCK_METHOD1(SendUserActionToUMA, bool(const std::string& action));

  bool AreMetricsEnabled() override {return metrics_enabled_;};
};

#endif  // METRICS_METRICS_LIBRARY_MOCK_H_

// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef METRICS_COUNTER_MOCK_H_
#define METRICS_COUNTER_MOCK_H_

#include <string>

#include <gmock/gmock.h>

#include "counter.h"

namespace chromeos_metrics {

class TaggedCounterMock : public TaggedCounter {
 public:
  MOCK_METHOD3(Init, void(const char* filename,
                          Reporter reporter, void* reporter_handle));
  MOCK_METHOD3(Update, void(uint32 report_tag, uint32 reset_tag, int32 count));
  MOCK_METHOD0(Flush, void());
};

class TaggedCounterReporterMock : public TaggedCounterReporter {
 public:
  MOCK_METHOD5(Init, void(const char* filename,
                          const char* histogram_name,
                          int min,
                          int max,
                          int nbuckets));
  MOCK_METHOD3(Update, void(uint32 report_tag, uint32 reset_tag, int32 count));
  MOCK_METHOD0(Flush, void());
};

class FrequencyCounterMock : public FrequencyCounter {
 public:
  MOCK_METHOD2(Init, void(TaggedCounterInterface* tagged_counter,
                          time_t cycle_duration));
  MOCK_METHOD1(Update, void(int32 count));
  MOCK_METHOD0(FlushFinishedCycles, void());
};

}  // namespace chromeos_metrics

#endif  // METRICS_COUNTER_MOCK_H_

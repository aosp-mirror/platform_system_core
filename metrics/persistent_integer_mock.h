// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef METRICS_PERSISTENT_INTEGER_MOCK_H_
#define METRICS_PERSISTENT_INTEGER_MOCK_H_

#include <string>

#include <gmock/gmock.h>

#include "metrics/persistent_integer.h"

namespace chromeos_metrics {

class PersistentIntegerMock : public PersistentInteger {
 public:
  explicit PersistentIntegerMock(const std::string& name)
      : PersistentInteger(name) {}
    MOCK_METHOD1(Add, void(int64 count));
};

}  // namespace chromeos_metrics

#endif  // METRICS_PERSISTENT_INTEGER_MOCK_H_

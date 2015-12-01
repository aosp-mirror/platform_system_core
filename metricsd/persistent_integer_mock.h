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

#ifndef METRICS_PERSISTENT_INTEGER_MOCK_H_
#define METRICS_PERSISTENT_INTEGER_MOCK_H_

#include <string>

#include <gmock/gmock.h>

#include "persistent_integer.h"

namespace chromeos_metrics {

class PersistentIntegerMock : public PersistentInteger {
 public:
  explicit PersistentIntegerMock(const std::string& name,
                                 const base::FilePath& directory)
      : PersistentInteger(name, directory) {}
  MOCK_METHOD1(Add, void(int64_t count));
};

}  // namespace chromeos_metrics

#endif  // METRICS_PERSISTENT_INTEGER_MOCK_H_

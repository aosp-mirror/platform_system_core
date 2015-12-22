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

#include <memory>

#include <base/compiler_specific.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <gtest/gtest.h>

#include "persistent_integer.h"

const char kBackingFileName[] = "1.pibakf";

using chromeos_metrics::PersistentInteger;

class PersistentIntegerTest : public testing::Test {
  void SetUp() override {
    // Set testing mode.
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
  }

 protected:
  base::ScopedTempDir temp_dir_;
};

TEST_F(PersistentIntegerTest, BasicChecks) {
  std::unique_ptr<PersistentInteger> pi(
      new PersistentInteger(kBackingFileName, temp_dir_.path()));

  // Test initialization.
  EXPECT_EQ(0, pi->Get());
  EXPECT_EQ(kBackingFileName, pi->Name());  // boring

  // Test set and add.
  pi->Set(2);
  pi->Add(3);
  EXPECT_EQ(5, pi->Get());

  // Test persistence.
  pi.reset(new PersistentInteger(kBackingFileName, temp_dir_.path()));
  EXPECT_EQ(5, pi->Get());

  // Test GetAndClear.
  EXPECT_EQ(5, pi->GetAndClear());
  EXPECT_EQ(pi->Get(), 0);

  // Another persistence test.
  pi.reset(new PersistentInteger(kBackingFileName, temp_dir_.path()));
  EXPECT_EQ(0, pi->Get());
}

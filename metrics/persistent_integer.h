// Copyright (c) 2014 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef METRICS_PERSISTENT_INTEGER_H_
#define METRICS_PERSISTENT_INTEGER_H_

#include <stdint.h>

#include <string>

namespace chromeos_metrics {

// PersistentIntegers is a named 64-bit integer value backed by a file.
// The in-memory value acts as a write-through cache of the file value.
// If the backing file doesn't exist or has bad content, the value is 0.

class PersistentInteger {
 public:
  explicit PersistentInteger(const std::string& name);

  // Virtual only because of mock.
  virtual ~PersistentInteger();

  // Sets the value.  This writes through to the backing file.
  void Set(int64_t v);

  // Gets the value.  May sync from backing file first.
  int64_t Get();

  // Returns the name of the object.
  std::string Name() { return name_; }

  // Convenience function for Get() followed by Set(0).
  int64_t GetAndClear();

  // Convenience function for v = Get, Set(v + x).
  // Virtual only because of mock.
  virtual void Add(int64_t x);

  // After calling with |testing| = true, changes some behavior for the purpose
  // of testing.  For instance: instances created while testing use the current
  // directory for the backing files.
  static void SetTestingMode(bool testing);

 private:
  static const int kVersion = 1001;

  // Writes |value_| to the backing file, creating it if necessary.
  void Write();

  // Reads the value from the backing file, stores it in |value_|, and returns
  // true if the backing file is valid.  Returns false otherwise, and creates
  // a valid backing file as a side effect.
  bool Read();

  int64_t value_;
  int32_t version_;
  std::string name_;
  std::string backing_file_name_;
  bool synced_;
  static bool testing_;
};

}  // namespace chromeos_metrics

#endif  // METRICS_PERSISTENT_INTEGER_H_

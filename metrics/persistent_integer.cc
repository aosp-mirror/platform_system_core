// Copyright (c) 2014 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "metrics/persistent_integer.h"

#include <fcntl.h>

#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>

#include "metrics/metrics_library.h"

namespace {

// The directory for the persistent storage.
const char kBackingFilesDirectory[] = "/var/lib/metrics/";

}

namespace chromeos_metrics {

// Static class member instantiation.
bool PersistentInteger::testing_ = false;

PersistentInteger::PersistentInteger(const std::string& name) :
      value_(0),
      version_(kVersion),
      name_(name),
      synced_(false) {
  if (testing_) {
    backing_file_name_ = name_;
  } else {
    backing_file_name_ = kBackingFilesDirectory + name_;
  }
}

PersistentInteger::~PersistentInteger() {}

void PersistentInteger::Set(int64_t value) {
  value_ = value;
  Write();
}

int64_t PersistentInteger::Get() {
  // If not synced, then read.  If the read fails, it's a good idea to write.
  if (!synced_ && !Read())
    Write();
  return value_;
}

int64_t PersistentInteger::GetAndClear() {
  int64_t v = Get();
  Set(0);
  return v;
}

void PersistentInteger::Add(int64_t x) {
  Set(Get() + x);
}

void PersistentInteger::Write() {
  int fd = HANDLE_EINTR(open(backing_file_name_.c_str(),
                             O_WRONLY | O_CREAT | O_TRUNC,
                             S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH));
  PCHECK(fd >= 0) << "cannot open " << backing_file_name_ << " for writing";
  PCHECK((HANDLE_EINTR(write(fd, &version_, sizeof(version_))) ==
          sizeof(version_)) &&
         (HANDLE_EINTR(write(fd, &value_, sizeof(value_))) ==
          sizeof(value_)))
      << "cannot write to " << backing_file_name_;
  close(fd);
  synced_ = true;
}

bool PersistentInteger::Read() {
  int fd = HANDLE_EINTR(open(backing_file_name_.c_str(), O_RDONLY));
  if (fd < 0) {
    PLOG(WARNING) << "cannot open " << backing_file_name_ << " for reading";
    return false;
  }
  int32_t version;
  int64_t value;
  bool read_succeeded = false;
  if (HANDLE_EINTR(read(fd, &version, sizeof(version))) == sizeof(version) &&
      version == version_ &&
      HANDLE_EINTR(read(fd, &value, sizeof(value))) == sizeof(value)) {
    value_ = value;
    read_succeeded = true;
    synced_ = true;
  }
  close(fd);
  return read_succeeded;
}

void PersistentInteger::SetTestingMode(bool testing) {
  testing_ = testing;
}


}  // namespace chromeos_metrics

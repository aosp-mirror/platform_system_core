// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "counter.h"

#include <fcntl.h>

#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>

#include "metrics_library.h"

namespace chromeos_metrics {

// TaggedCounter::Record implementation.
void TaggedCounter::Record::Init(uint32 report_tag,
                                 uint32 reset_tag,
                                 int32 count) {
  report_tag_ = report_tag;
  reset_tag_ = reset_tag;
  count_ = (count > 0) ? count : 0;
}

void TaggedCounter::Record::Add(int32 count) {
  if (count <= 0)
    return;

  // Saturates on positive overflow.
  int64 new_count = static_cast<int64>(count_) + static_cast<int64>(count);
  if (new_count > kint32max)
    count_ = kint32max;
  else
    count_ = static_cast<int32>(new_count);
}

// TaggedCounter implementation.
TaggedCounter::TaggedCounter()
    : reporter_(NULL),
      reporter_handle_(NULL),
      record_state_(kRecordInvalid) {}

TaggedCounter::~TaggedCounter() {}

void TaggedCounter::Init(const char* filename,
                         Reporter reporter, void* reporter_handle) {
  DCHECK(filename);
  filename_ = filename;
  reporter_ = reporter;
  reporter_handle_ = reporter_handle;
  record_state_ = kRecordInvalid;
}

void TaggedCounter::Update(uint32 report_tag, uint32 reset_tag, int32 count) {
  UpdateInternal(report_tag,
                 reset_tag,
                 count,
                 false);  // No flush.
}

void TaggedCounter::Flush() {
  UpdateInternal(0,  // report_tag
                 0,  // reset_tag
                 0,  // count
                 true);  // Do flush.
}

void TaggedCounter::UpdateInternal(uint32 report_tag,
                                   uint32 reset_tag,
                                   int32 count,
                                   bool flush) {
  if (flush) {
    // Flushing but record is null, so nothing to do.
    if (record_state_ == kRecordNull)
      return;
  } else {
    // If there's no new data and the last record in the aggregation
    // file is with the same tag, there's nothing to do.
    if (count <= 0 &&
        record_state_ == kRecordValid &&
        record_.report_tag() == report_tag &&
        record_.reset_tag() == reset_tag)
      return;
  }

  DLOG(INFO) << "report_tag: " << report_tag << " reset_tag: " << reset_tag
             << " count: " << count << " flush: " << flush;
  DCHECK(!filename_.empty());

  // NOTE: The assumption is that this TaggedCounter object is the
  // sole owner of the persistent storage file so no locking is
  // necessary.
  int fd = HANDLE_EINTR(open(filename_.c_str(),
                             O_RDWR | O_CREAT, S_IRUSR | S_IWUSR));
  if (fd < 0) {
    PLOG(WARNING) << "Unable to open the persistent counter file";
    return;
  }
  ReadRecord(fd);
  ReportRecord(report_tag, reset_tag, flush);
  UpdateRecord(report_tag, reset_tag, count, flush);
  WriteRecord(fd);

  HANDLE_EINTR(close(fd));
}

void TaggedCounter::ReadRecord(int fd) {
  if (record_state_ != kRecordInvalid)
    return;

  // Three cases: 1. empty file (first time), 2. size of file == size of record
  // (normal case), 3. size of file != size of record (new version).  We treat
  // cases 1 and 3 identically.
  if (HANDLE_EINTR(read(fd, &record_, sizeof(record_))) == sizeof(record_)) {
    if (record_.count() >= 0) {
      record_state_ = kRecordValid;
      return;
    }
    // This shouldn't happen normally unless somebody messed with the
    // persistent storage file.
    NOTREACHED();
    record_state_ = kRecordNullDirty;
    return;
  }
  record_state_ = kRecordNull;
}

void TaggedCounter::ReportRecord(uint32 report_tag,
                                 uint32 reset_tag,
                                 bool flush) {
  // If no valid record, there's nothing to report.
  if (record_state_ != kRecordValid) {
    DCHECK_EQ(record_state_, kRecordNull);
    return;
  }

  // If the current record has the same tags as the new ones, it's
  // not ready to be reported yet.
  if (!flush &&
      record_.report_tag() == report_tag &&
      record_.reset_tag() == reset_tag)
    return;

  if (reporter_) {
    reporter_(reporter_handle_, record_.count());
  }
  // If the report tag has changed, update it to the current one.
  if (record_.report_tag() != report_tag) {
    record_.set_report_tag(report_tag);
    record_state_ = kRecordValidDirty;
  }
  // If the reset tag has changed, the new state is NullDirty, no
  // matter whether the report tag has changed or not.
  if (record_.reset_tag() != reset_tag) {
    record_state_ = kRecordNullDirty;
  }
}

void TaggedCounter::UpdateRecord(uint32 report_tag,
                                 uint32 reset_tag,
                                 int32 count,
                                 bool flush) {
  if (flush &&
      (record_state_ == kRecordNull || record_state_ == kRecordNullDirty))
    return;

  switch (record_state_) {
    case kRecordNull:
    case kRecordNullDirty:
      // Current record is null, starting a new record.
      record_.Init(report_tag, reset_tag, count);
      record_state_ = kRecordValidDirty;
      break;

    case kRecordValid:
    case kRecordValidDirty:
      // If there's an existing record for the current tag,
      // accumulates the counts.
      DCHECK_EQ(record_.report_tag(), report_tag);
      DCHECK_EQ(record_.reset_tag(), reset_tag);
      if (count > 0) {
        record_.Add(count);
        record_state_ = kRecordValidDirty;
      }
      break;

    default:
      NOTREACHED();
  }
}

void TaggedCounter::WriteRecord(int fd) {
  switch (record_state_) {
    case kRecordNullDirty:
      // Truncates the aggregation file to discard the record.
      PLOG_IF(WARNING, HANDLE_EINTR(ftruncate(fd, 0)) != 0);
      record_state_ = kRecordNull;
      break;

    case kRecordValidDirty:
      // Updates the accumulator record in the file if there's new data.
      PLOG_IF(WARNING, HANDLE_EINTR(lseek(fd, 0, SEEK_SET)) != 0);
      PLOG_IF(WARNING,
              HANDLE_EINTR(write(fd, &record_, sizeof(record_))) !=
              sizeof(record_));
      record_state_ = kRecordValid;
      break;

    case kRecordNull:
    case kRecordValid:
      // Nothing to do.
      break;

    default:
      NOTREACHED();
  }
}

MetricsLibraryInterface* TaggedCounterReporter::metrics_lib_ = NULL;

TaggedCounterReporter::TaggedCounterReporter()
    : tagged_counter_(new TaggedCounter()),
      min_(0),
      max_(0),
      buckets_(0) {
}

TaggedCounterReporter::~TaggedCounterReporter() {
}

void TaggedCounterReporter::Init(const char* filename,
                                 const char* histogram_name,
                                 int min,
                                 int max,
                                 int buckets) {
  tagged_counter_->Init(filename, Report, this);
  histogram_name_ = histogram_name;
  min_ = min;
  max_ = max;
  buckets_ = buckets;
  CHECK(min_ >= 0);
  CHECK(max_ > min_);
  CHECK(buckets_ > 0);
}

void TaggedCounterReporter::Report(void* handle, int32 count) {
  TaggedCounterReporter* this_reporter =
      reinterpret_cast<TaggedCounterReporter*>(handle);
  DLOG(INFO) << "received metric: " << this_reporter->histogram_name_
             << " " << count << " " << this_reporter->min_ << " "
             << this_reporter->max_ << " " << this_reporter->buckets_;
  CHECK(metrics_lib_ != NULL);
  CHECK(this_reporter->buckets_ > 0);
  metrics_lib_->SendToUMA(this_reporter->histogram_name_,
                          count,
                          this_reporter->min_,
                          this_reporter->max_,
                          this_reporter->buckets_);
}

FrequencyCounter::FrequencyCounter() : cycle_duration_(1) {
}

FrequencyCounter::~FrequencyCounter() {
}

void FrequencyCounter::Init(TaggedCounterInterface* tagged_counter,
                            time_t cycle_duration) {
  tagged_counter_.reset(tagged_counter);
  DCHECK_GT(cycle_duration, 0);
  cycle_duration_ = cycle_duration;
}

void FrequencyCounter::UpdateInternal(int32 count, time_t now) {
  DCHECK(tagged_counter_.get());
  tagged_counter_->Update(0, GetCycleNumber(now), count);
}

int32 FrequencyCounter::GetCycleNumber(time_t now) {
  return now / cycle_duration_;
}

VersionCounter::VersionCounter() : cycle_duration_(1) {
}

VersionCounter::~VersionCounter() {
}

void VersionCounter::Init(TaggedCounterInterface* tagged_counter,
                          time_t cycle_duration) {
  tagged_counter_.reset(tagged_counter);
  DCHECK_GT(cycle_duration, 0);
  cycle_duration_ = cycle_duration;
}

void VersionCounter::UpdateInternal(int32 count,
                                    time_t now,
                                    uint32 version_hash) {
  DCHECK(tagged_counter_.get());
  tagged_counter_->Update(GetCycleNumber(now), version_hash, count);
}

int32 VersionCounter::GetCycleNumber(time_t now) {
  return now / cycle_duration_;
}

}  // namespace chromeos_metrics

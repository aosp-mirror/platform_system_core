// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "counter.h"

#include <fcntl.h>

#include <base/eintr_wrapper.h>
#include <base/logging.h>

namespace chromeos_metrics {

// TaggedCounter::Record implementation.
void TaggedCounter::Record::Init(int32 tag, int32 count) {
  tag_ = tag;
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
    : filename_(NULL),
      reporter_(NULL),
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

void TaggedCounter::Update(int32 tag, int32 count) {
  UpdateInternal(tag,
                 count,
                 false);  // No flush.
}

void TaggedCounter::Flush() {
  UpdateInternal(0,  // tag
                 0,  // count
                 true);  // Do flush.
}

void TaggedCounter::UpdateInternal(int32 tag, int32 count, bool flush) {
  if (flush) {
    // Flushing but record is null, so nothing to do.
    if (record_state_ == kRecordNull)
      return;
  } else {
    // If there's no new data and the last record in the aggregation
    // file is with the same tag, there's nothing to do.
    if (count <= 0 && record_state_ == kRecordValid && record_.tag() == tag)
      return;
  }

  DLOG(INFO) << "tag: " << tag << " count: " << count << " flush: " << flush;
  DCHECK(filename_);

  // NOTE: The assumption is that this TaggedCounter object is the
  // sole owner of the persistent storage file so no locking is
  // necessary.
  int fd = HANDLE_EINTR(open(filename_, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR));
  if (fd < 0) {
    PLOG(WARNING) << "Unable to open the persistent counter file";
    return;
  }

  ReadRecord(fd);
  ReportRecord(tag, flush);
  UpdateRecord(tag, count, flush);
  WriteRecord(fd);

  HANDLE_EINTR(close(fd));
}

void TaggedCounter::ReadRecord(int fd) {
  if (record_state_ != kRecordInvalid)
    return;

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

void TaggedCounter::ReportRecord(int32 tag, bool flush) {
  // If no valid record, there's nothing to report.
  if (record_state_ != kRecordValid) {
    DCHECK_EQ(record_state_, kRecordNull);
    return;
  }

  // If the current record has the same tag as the new tag, it's not
  // ready to be reported yet.
  if (!flush && record_.tag() == tag)
    return;

  if (reporter_) {
    reporter_(reporter_handle_, record_.tag(), record_.count());
  }
  record_state_ = kRecordNullDirty;
}

void TaggedCounter::UpdateRecord(int32 tag, int32 count, bool flush) {
  if (flush) {
    DCHECK(record_state_ == kRecordNull || record_state_ == kRecordNullDirty);
    return;
  }

  switch (record_state_) {
    case kRecordNull:
    case kRecordNullDirty:
      // Current record is null, starting a new record.
      record_.Init(tag, count);
      record_state_ = kRecordValidDirty;
      break;

    case kRecordValid:
      // If there's an existing record for the current tag,
      // accumulates the counts.
      DCHECK_EQ(record_.tag(), tag);
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

}  // namespace chromeos_metrics

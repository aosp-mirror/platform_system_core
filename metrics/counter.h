// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef METRICS_COUNTER_H_
#define METRICS_COUNTER_H_

#include <string>
#include <time.h>

#include <base/basictypes.h>
#include <base/memory/scoped_ptr.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST

class MetricsLibraryInterface;

namespace chromeos_metrics {

// Constants useful for frequency statistics.
const int kSecondsPerDay = 60 * 60 * 24;
const int kSecondsPerWeek = kSecondsPerDay * 7;

// TaggedCounter maintains a persistent storage (i.e., a file) aggregation
// counter for given tags (e.g., day, hour, version number) that survives
// system shutdowns, reboots and crashes, as well as daemon process
// restarts. The counter object is initialized by pointing to the persistent
// storage file and providing a callback used for reporting aggregated data.
// The counter can then be updated with additional event counts.  The
// aggregated count is reported through the callback when the counter is
// explicitly flushed or when data for a new tag arrives.
//
// The primary reason for using an interface is to allow easier unit
// testing in clients through mocking thus avoiding file access and
// callbacks. Of course, it also enables alternative implementations
// of the counter with additional features.
class TaggedCounterInterface {
 public:
  // Callback type used for reporting aggregated or flushed data.
  // Once this callback is invoked by the counter, the reported
  // aggregated data is discarded.
  //
  // |handle| is the |reporter_handle| pointer passed through Init.
  // |count| is aggregated count.
  typedef void (*Reporter)(void* handle, int32 count);

  virtual ~TaggedCounterInterface() {}

  // Adds |count| of events for the given tags. If there's an existing
  // aggregated count for different tags, it's reported through the reporter
  // callback, and optionally discarded, depending on whether |report_tag|
  // changed or |reset_tag| changed.
  virtual void Update(uint32 report_tag, uint32 reset_tag, int32 count) = 0;

  // Reports the current aggregated count (if any) through the
  // reporter callback and discards it.
  virtual void Flush() = 0;
};

class TaggedCounter : public TaggedCounterInterface {
 public:
  TaggedCounter();
  virtual ~TaggedCounter();

  // Initializes the counter by providing the persistent storage
  // location |filename| and a |reporter| callback for reporting
  // aggregated counts. |reporter_handle| is sent to the |reporter|
  // along with the aggregated counts.
  //
  // NOTE: The assumption is that this object is the sole owner of the
  // persistent storage file so no locking is currently implemented.
  virtual void Init(const char* filename,
                    Reporter reporter, void* reporter_handle);

  // Implementation of interface methods.
  virtual void Update(uint32 report_tag, uint32 reset_tag, int32 count);
  virtual void Flush();

 private:
  friend class RecordTest;
  friend class TaggedCounterTest;
  FRIEND_TEST(TaggedCounterTest, BadFileLocation);
  FRIEND_TEST(TaggedCounterTest, Flush);
  FRIEND_TEST(TaggedCounterTest, InitFromFile);
  FRIEND_TEST(TaggedCounterTest, Update);

  // The current record is cached by the counter object to
  // avoid potentially unnecessary I/O. The cached record can be in
  // one of the following states:
  enum RecordState {
    kRecordInvalid,    // Invalid record, sync from persistent storage needed.
    kRecordNull,       // No current record, persistent storage synced.
    kRecordNullDirty,  // No current record, persistent storage is invalid.
    kRecordValid,      // Current record valid, persistent storage synced.
    kRecordValidDirty  // Current record valid, persistent storage is invalid.
  };

  // Defines the record. Objects of this class are synced
  // with the persistent storage through binary reads/writes.
  class Record {
   public:
    // Creates a new Record with all fields reset to 0.
  Record() : report_tag_(0), reset_tag_(0), count_(0) {}

    // Initializes with |report_tag|, |reset_tag| and |count|.
    // If |count| is negative, |count_| is set to 0.
    void Init(uint32 report_tag, uint32 reset_tag, int32 count);

    // Adds |count| to the current |count_|. Negative |count| is
    // ignored. In case of positive overflow, |count_| is saturated to
    // kint32max.
    void Add(int32 count);

    uint32 report_tag() const { return report_tag_; }
    void set_report_tag(uint32 report_tag) { report_tag_ = report_tag; }
    uint32 reset_tag() const { return reset_tag_; }
    int32 count() const { return count_; }

   private:
    // When |report_tag_| changes, the counter is reported as a UMA sample.
    // When |reset_tag_| changes, the counter is both reported and reset.
    uint32 report_tag_;
    uint32 reset_tag_;
    int32 count_;
  };

  // Implementation of the Update and Flush methods. Goes through the
  // necessary steps to read, report, update, and sync the aggregated
  // record.
  void UpdateInternal(uint32 report_tag,
                      uint32 reset_tag,
                      int32 count,
                      bool flush);

  // If the current cached record is invalid, reads it from persistent
  // storage specified through file descriptor |fd| and updates the
  // cached record state to either null, or valid depending on the
  // persistent storage contents.
  void ReadRecord(int fd);

  // If there's an existing valid record and either |flush| is true, or either
  // new tag is different than the old one, reports the aggregated data through
  // the reporter callback, and possibly resets the cached record.
  void ReportRecord(uint32 report_tag, uint32 reset_tag, bool flush);

  // Updates the cached record given the new tags and |count|. This
  // method expects either a null cached record, or a valid cached
  // record with the same tags as given. If |flush| is true, the method
  // asserts that the cached record is null and returns.
  void UpdateRecord(uint32 report_tag,
                    uint32 reset_tag,
                    int32 count,
                    bool flush);

  // If the cached record state is dirty, updates the persistent
  // storage specified through file descriptor |fd| and switches the
  // record state to non-dirty.
  void WriteRecord(int fd);

  // Persistent storage file path.
  std::string filename_;

  // Aggregated data reporter callback and handle to pass-through.
  Reporter reporter_;
  void* reporter_handle_;

  // Current cached aggregation record.
  Record record_;

  // Current cached aggregation record state.
  RecordState record_state_;
};

// TaggedCounterReporter provides a TaggedCounterInterface which both
// counts tagged events and reports them up through the metrics
// library to UMA.
class TaggedCounterReporter : public TaggedCounterInterface {
 public:
  TaggedCounterReporter();
  virtual ~TaggedCounterReporter();

  // Set the metrics library used by all TaggedCounterReporter
  // instances.  We assume there is only one metrics library
  // shared amongst all reporters.
  static void SetMetricsLibraryInterface(MetricsLibraryInterface* metrics_lib) {
    metrics_lib_ = metrics_lib;
  }

  // Initializes the counter by providing the persistent storage
  // location |filename|, a |histogram_name| (a linear histogram) to
  // report to with |min|, |max|, and |buckets| attributes for the
  // histogram.
  virtual void Init(const char* filename,
                    const char* histogram_name,
                    int min,
                    int max,
                    int buckets);

  // Implementation of interface method.
  virtual void Update(uint32 report_tag, uint32 reset_tag, int32 count) {
    tagged_counter_->Update(report_tag, reset_tag, count);
  }
  // Implementation of interface method.
  virtual void Flush() {
    tagged_counter_->Flush();
  }

  // Accessor functions.
  const std::string& histogram_name() const {
    return histogram_name_;
  }

  int min() const {
    return min_;
  }

  int max() const {
    return max_;
  }

  int buckets() const {
    return buckets_;
  }

 protected:
  friend class TaggedCounterReporterTest;
  FRIEND_TEST(TaggedCounterReporterTest, Report);

  static void Report(void* handle, int32 count);

  static MetricsLibraryInterface* metrics_lib_;
  scoped_ptr<TaggedCounter> tagged_counter_;
  std::string histogram_name_;
  int min_;
  int max_;
  int buckets_;
};

// FrequencyCounter uses TaggedCounter to maintain a persistent
// storage of the number of events that occur in a given cycle
// duration (in other words, a frequency count).  For example, to
// count the number of blips per day, initialize |cycle_duration| to
// chromeos_metrics::kSecondsPerDay, and call Update with the number
// of blips that happen concurrently (usually 1).  Reporting of the
// value is done through TaggedCounter's reporter function.
class FrequencyCounter {
 public:
  // Create a new frequency counter.
  FrequencyCounter();
  virtual ~FrequencyCounter();

  // Initialize a frequency counter, which is necessary before first
  // use.  |tagged_counter| is used to store the counts, its memory
  // will be managed by this FrequencyCounter.  |cycle_duration| is
  // the number of seconds in a cycle.
  virtual void Init(TaggedCounterInterface* tagged_counter,
                    time_t cycle_duration);
  // Record that an event occurred.  |count| is the number of concurrent
  // events that have occurred.  The time is implicitly assumed to be the
  // time of the call.
  virtual void Update(int32 count) {
    UpdateInternal(count, time(NULL));
  }

  // Update the frequency counter based on the current time.  If a
  // cycle has finished, this will have the effect of flushing the
  // cycle's count, without first requiring another update to the
  // frequency counter.  The more often this is called, the lower the
  // latency to have a new sample submitted.
  virtual void FlushFinishedCycles() {
    Update(0);
  }

  // Accessor function.
  const TaggedCounterInterface& tagged_counter() const {
    return *tagged_counter_;
  }

  time_t cycle_duration() const {
    return cycle_duration_;
  }

 private:
  friend class FrequencyCounterTest;
  FRIEND_TEST(FrequencyCounterTest, UpdateInternal);
  FRIEND_TEST(FrequencyCounterTest, GetCycleNumberForWeek);
  FRIEND_TEST(FrequencyCounterTest, GetCycleNumberForDay);

  void UpdateInternal(int32 count, time_t now);
  int32 GetCycleNumber(time_t now);

  time_t cycle_duration_;
  scoped_ptr<TaggedCounterInterface> tagged_counter_;
};

// VersionCounter is like a FrequencyCounter, but it exposes
// separate "report" and "reset" tags, for counters that should
// be reported more often than they are reset.
class VersionCounter {
 public:
  VersionCounter();
  virtual ~VersionCounter();

  // Initialize a version counter, which is necessary before first use.
  // |tagged_counter| is used to store the counts.  Its memory is managed
  // by this FrequencyCounter.  |cycle_duration| is the number of seconds in a
  // cycle.
  virtual void Init(TaggedCounterInterface* tagged_counter,
                    time_t cycle_duration);
  // Record that |count| events have occurred. The
  // time is implicitly assumed to be the time of the call.
  // The version hash is passed.
  virtual void Update(int32 count, uint32 version_hash) {
    UpdateInternal(count, time(NULL), version_hash);
  }

  // Reports the counter if enough time has passed, and also resets it if the
  // version number has changed.
  virtual void FlushOnChange(uint32 version_hash) {
    UpdateInternal(0, time(NULL), version_hash);
  }

  // Accessor function.
  const TaggedCounterInterface& tagged_counter() const {
    return *tagged_counter_;
  }

  time_t cycle_duration() const {
    return cycle_duration_;
  }

 private:
  friend class VersionCounterTest;
  FRIEND_TEST(VersionCounterTest, UpdateInternal);

  void UpdateInternal(int32 count, time_t now, uint32 version_hash);
  // TODO(semenzato): it's generally better to use base::TimeTicks (for
  // monotonically-increasing timestamps) or base::Time (for wall time)
  int32 GetCycleNumber(time_t now);
  time_t cycle_duration_;
  scoped_ptr<TaggedCounterInterface> tagged_counter_;
};

}  // namespace chromeos_metrics

#endif  // METRICS_COUNTER_H_

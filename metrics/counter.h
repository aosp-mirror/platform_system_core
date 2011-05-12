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

// TaggedCounter maintains a persistent storage (i.e., a file)
// aggregation counter for a given tag (e.g., day, hour) that survives
// system shutdowns, reboots and crashes, as well as daemon process
// restarts. The counter object is initialized by pointing to the
// persistent storage file and providing a callback used for reporting
// aggregated data.  The counter can then be updated with additional
// event counts.  The aggregated count is reported through the
// callback when the counter is explicitly flushed or when data for a
// new tag arrives.
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
  // |tag| is the tag associated with the aggregated count.
  // |count| is aggregated count.
  typedef void (*Reporter)(void* handle, int32 tag, int32 count);

  virtual ~TaggedCounterInterface() {}

  // Adds |count| of events for the given |tag|. If there's an
  // existing aggregated count for a different tag, it's reported
  // through the reporter callback and discarded.
  virtual void Update(int32 tag, int32 count) = 0;

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
  virtual void Update(int32 tag, int32 count);
  virtual void Flush();

 private:
  friend class RecordTest;
  friend class TaggedCounterTest;
  FRIEND_TEST(TaggedCounterTest, BadFileLocation);
  FRIEND_TEST(TaggedCounterTest, Flush);
  FRIEND_TEST(TaggedCounterTest, InitFromFile);
  FRIEND_TEST(TaggedCounterTest, Update);

  // The current tag/count record is cached by the counter object to
  // avoid potentially unnecessary I/O. The cached record can be in
  // one of the following states:
  enum RecordState {
    kRecordInvalid,    // Invalid record, sync from persistent storage needed.
    kRecordNull,       // No current record, persistent storage synced.
    kRecordNullDirty,  // No current record, persistent storage is invalid.
    kRecordValid,      // Current record valid, persistent storage synced.
    kRecordValidDirty  // Current record valid, persistent storage is invalid.
  };

  // Defines the tag/count record. Objects of this class are synced
  // with the persistent storage through binary reads/writes.
  class Record {
   public:
    // Creates a new Record with |tag_| and |count_| reset to 0.
    Record() : tag_(0), count_(0) {}

    // Initializes with |tag| and |count|. If |count| is negative,
    // |count_| is set to 0.
    void Init(int32 tag, int32 count);

    // Adds |count| to the current |count_|. Negative |count| is
    // ignored. In case of positive overflow, |count_| is saturated to
    // kint32max.
    void Add(int32 count);

    int32 tag() const { return tag_; }
    int32 count() const { return count_; }

   private:
    int32 tag_;
    int32 count_;
  };

  // Implementation of the Update and Flush methods. Goes through the
  // necessary steps to read, report, update, and sync the aggregated
  // record.
  void UpdateInternal(int32 tag, int32 count, bool flush);

  // If the current cached record is invalid, reads it from persistent
  // storage specified through file descriptor |fd| and updates the
  // cached record state to either null, or valid depending on the
  // persistent storage contents.
  void ReadRecord(int fd);

  // If there's an existing valid record and either |flush| is true,
  // or the new |tag| is different than the old one, reports the
  // aggregated data through the reporter callback and resets the
  // cached record.
  void ReportRecord(int32 tag, bool flush);

  // Updates the cached record given the new |tag| and |count|. This
  // method expects either a null cached record, or a valid cached
  // record with the same tag as |tag|. If |flush| is true, the method
  // asserts that the cached record is null and returns.
  void UpdateRecord(int32 tag, int32 count, bool flush);

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
  virtual void Update(int32 tag, int32 count) {
    tagged_counter_->Update(tag, count);
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

  static void Report(void* handle, int32 tag, int32 count);

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

}  // namespace chromeos_metrics

#endif  // METRICS_COUNTER_H_

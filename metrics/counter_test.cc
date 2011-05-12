// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <sys/file.h>

#include <base/eintr_wrapper.h>
#include <base/file_util.h>
#include <base/logging.h>
#include <base/string_util.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "counter.h"
#include "counter_mock.h"  // For TaggedCounterMock.
#include "metrics_library_mock.h"

using ::testing::_;
using ::testing::MockFunction;
using ::testing::StrictMock;

namespace chromeos_metrics {

static const char kTestRecordFile[] = "record-file";
static const char kDoesNotExistFile[] = "/does/not/exist";

class RecordTest : public testing::Test {
 protected:
  virtual void SetUp() {
    EXPECT_EQ(0, record_.tag());
    EXPECT_EQ(0, record_.count());
  }

  // The record under test.
  TaggedCounter::Record record_;
};

class TaggedCounterTest : public testing::Test {
 protected:
  virtual void SetUp() {
    EXPECT_TRUE(counter_.filename_.empty());
    EXPECT_TRUE(NULL == counter_.reporter_);
    EXPECT_EQ(NULL, counter_.reporter_handle_);
    EXPECT_EQ(TaggedCounter::kRecordInvalid, counter_.record_state_);

    counter_.Init(kTestRecordFile, &Reporter, this);
    EXPECT_TRUE(AssertNoOrEmptyRecordFile());
    EXPECT_EQ(kTestRecordFile, counter_.filename_);
    EXPECT_TRUE(Reporter == counter_.reporter_);
    EXPECT_EQ(this, counter_.reporter_handle_);
    EXPECT_EQ(TaggedCounter::kRecordInvalid, counter_.record_state_);

    // The test fixture object will be used by the log message handler.
    test_ = this;
    logging::SetLogMessageHandler(HandleLogMessages);
  }

  virtual void TearDown() {
    logging::SetLogMessageHandler(NULL);
    test_ = NULL;
    file_util::Delete(FilePath(kTestRecordFile), false);
  }

  // Asserts that the record file contains the specified contents.
  testing::AssertionResult AssertRecord(const char* expr_tag,
                                        const char* expr_count,
                                        int32 expected_tag,
                                        int32 expected_count) {
    int fd = HANDLE_EINTR(open(kTestRecordFile, O_RDONLY));
    if (fd < 0) {
      testing::Message msg;
      msg << "Unable to open " << kTestRecordFile;
      return testing::AssertionFailure(msg);
    }

    TaggedCounter::Record record;
    if (!file_util::ReadFromFD(fd, reinterpret_cast<char*>(&record),
                               sizeof(record))) {
      testing::Message msg;
      msg << "Unable to read " << sizeof(record) << " bytes from "
          << kTestRecordFile;
      HANDLE_EINTR(close(fd));
      return testing::AssertionFailure(msg);
    }

    if (record.tag() != expected_tag || record.count() != expected_count) {
      testing::Message msg;
      msg << "actual record (" << record.tag() << ", " << record.count()
          << ") expected (" << expected_tag << ", " << expected_count << ")";
      HANDLE_EINTR(close(fd));
      return testing::AssertionFailure(msg);
    }

    HANDLE_EINTR(close(fd));
    return testing::AssertionSuccess();
  }

  // Returns true if the persistent record file does not exist or is
  // empty, false otherwise.
  bool AssertNoOrEmptyRecordFile() {
    FilePath record_file(counter_.filename_);
    int64 record_file_size;
    return !file_util::PathExists(record_file) ||
        (file_util::GetFileSize(record_file, &record_file_size) &&
         record_file_size == 0);
  }

  // Adds a reporter call expectation that the specified tag/count
  // callback will be generated.
  void ExpectReporterCall(int32 tag, int32 count) {
    EXPECT_CALL(reporter_, Call(_, tag, count))
        .Times(1)
        .RetiresOnSaturation();
  }

  // The reporter callback forwards the call to the reporter mock so
  // that we can set call expectations.
  static void Reporter(void* handle, int32 tag, int32 count) {
    TaggedCounterTest* test = static_cast<TaggedCounterTest*>(handle);
    ASSERT_FALSE(NULL == test);
    test->reporter_.Call(handle, tag, count);
  }

  // Collects log messages in the |log_| member string so that they
  // can be analyzed for errors and expected behavior.
  static bool HandleLogMessages(int severity,
                                const char* file,
                                int line,
                                size_t message_start,
                                const std::string& str) {
    test_->log_.append(str);
    test_->log_.append("\n");

    // Returning true would mute the log.
    return false;
  }

  // Returns true if the counter log contains |pattern|, false otherwise.
  bool LogContains(const std::string& pattern) const {
    return log_.find(pattern) != std::string::npos;
  }

  // The TaggedCounter object under test.
  TaggedCounter counter_;

  // The accumulated counter log.
  std::string log_;

  // Reporter mock to set callback expectations on.
  StrictMock<MockFunction<void(void* handle,
                               int32 tag, int32 count)> > reporter_;

  // Pointer to the current test fixture.
  static TaggedCounterTest* test_;
};

// static
TaggedCounterTest* TaggedCounterTest::test_ = NULL;

TEST_F(RecordTest, Init) {
  record_.Init(/* tag */ 5, /* count */ -1);
  EXPECT_EQ(5, record_.tag());
  EXPECT_EQ(0, record_.count());

  record_.Init(/* tag */ -2, /* count */ 10);
  EXPECT_EQ(-2, record_.tag());
  EXPECT_EQ(10, record_.count());
}

TEST_F(RecordTest, Add) {
  record_.Add(/* count */ -1);
  EXPECT_EQ(0, record_.count());

  record_.Add(/* count */ 5);
  EXPECT_EQ(5, record_.count());

  record_.Add(/* count */ 10);
  EXPECT_EQ(15, record_.count());

  record_.Add(/* count */ -2);
  EXPECT_EQ(15, record_.count());

  record_.Add(/* count */ kint32max);
  EXPECT_EQ(kint32max, record_.count());

  record_.Add(/* count */ 1);
  EXPECT_EQ(kint32max, record_.count());
}

TEST_F(TaggedCounterTest, BadFileLocation) {
  // Checks that the counter doesn't die badly if the file can't be
  // created.
  counter_.Init(kDoesNotExistFile,
                /* reporter */ NULL, /* reporter_handle */ NULL);
  counter_.Update(/* tag */ 10, /* count */ 20);
  EXPECT_TRUE(LogContains("Unable to open the persistent counter file: "
                          "No such file or directory"));
  EXPECT_EQ(TaggedCounter::kRecordInvalid, counter_.record_state_);
  file_util::Delete(FilePath(kDoesNotExistFile), false);
}

TEST_F(TaggedCounterTest, Flush) {
  counter_.Flush();
  EXPECT_EQ(TaggedCounter::kRecordNull, counter_.record_state_);

  counter_.Update(/* tag */ 40, /* count */ 60);
  ExpectReporterCall(/* tag */ 40, /* count */ 60);
  counter_.Flush();
  EXPECT_TRUE(AssertNoOrEmptyRecordFile());
  EXPECT_EQ(TaggedCounter::kRecordNull, counter_.record_state_);

  counter_.Update(/* tag */ 41, /* count */ 70);
  counter_.record_.Init(/* tag */ 0, /* count */ 0);
  counter_.record_state_ = TaggedCounter::kRecordInvalid;
  ExpectReporterCall(/* tag */ 41, /* count */ 70);
  counter_.Flush();
  EXPECT_TRUE(AssertNoOrEmptyRecordFile());
  EXPECT_EQ(TaggedCounter::kRecordNull, counter_.record_state_);
}

TEST_F(TaggedCounterTest, InitFromFile) {
  counter_.Update(/* tag */ 30, /* count */ 50);
  EXPECT_PRED_FORMAT2(AssertRecord, /* day */ 30, /* seconds */ 50);
  EXPECT_EQ(TaggedCounter::kRecordValid, counter_.record_state_);

  counter_.Init(kTestRecordFile, &Reporter, this);
  counter_.Update(/* tag */ 30, /* count */ 40);
  EXPECT_PRED_FORMAT2(AssertRecord, /* day */ 30, /* seconds */ 90);
  EXPECT_EQ(TaggedCounter::kRecordValid, counter_.record_state_);

  counter_.Init(kTestRecordFile, &Reporter, this);
  ExpectReporterCall(/* tag */ 30, /* count */ 90);
  counter_.Update(/* tag */ 31, /* count */ 60);
  EXPECT_PRED_FORMAT2(AssertRecord, /* day */ 31, /* seconds */ 60);
  EXPECT_EQ(TaggedCounter::kRecordValid, counter_.record_state_);

  ExpectReporterCall(/* tag */ 31, /* count */ 60);
  counter_.Init(kTestRecordFile, &Reporter, this);
  counter_.Update(/* tag */ 32, /* count */ 0);
  EXPECT_PRED_FORMAT2(AssertRecord, /* day */ 32, /* seconds */ 0);
  EXPECT_EQ(TaggedCounter::kRecordValid, counter_.record_state_);
}

TEST_F(TaggedCounterTest, Update) {
  counter_.Update(/* tag */ 20, /* count */ 30);
  EXPECT_PRED_FORMAT2(AssertRecord, /* day */ 20, /* seconds */ 30);
  EXPECT_EQ(TaggedCounter::kRecordValid, counter_.record_state_);

  counter_.Update(/* tag */ 20, /* count */ 40);
  EXPECT_PRED_FORMAT2(AssertRecord, /* day */ 20, /* seconds */ 70);
  EXPECT_EQ(TaggedCounter::kRecordValid, counter_.record_state_);

  ExpectReporterCall(/* tag */ 20, /* count */ 70);
  counter_.Update(/* tag */ 21, /* count */ 15);
  EXPECT_PRED_FORMAT2(AssertRecord, /* day */ 21, /* seconds */ 15);
  EXPECT_EQ(TaggedCounter::kRecordValid, counter_.record_state_);

  ExpectReporterCall(/* tag */ 21, /* count */ 15);
  counter_.Update(/* tag */ 22, /* count */ 0);
  EXPECT_PRED_FORMAT2(AssertRecord, /* day */ 22, /* seconds */ 0);
  EXPECT_EQ(TaggedCounter::kRecordValid, counter_.record_state_);
}

static const char kTestFilename[] = "test_filename";
static const char kTestHistogram[] = "test_histogram";
const int kHistogramMin = 15;
const int kHistogramMax = 1024;
const int kHistogramBuckets = 23;

class TaggedCounterReporterTest : public testing::Test {
 protected:
  virtual void SetUp() {
    tagged_counter_ = new StrictMock<TaggedCounterMock>();
    reporter_.tagged_counter_.reset(tagged_counter_);
    metrics_lib_.reset(new StrictMock<MetricsLibraryMock>);
    reporter_.SetMetricsLibraryInterface(metrics_lib_.get());
    ASSERT_TRUE(metrics_lib_.get() == reporter_.metrics_lib_);
  }
  virtual void TearDown() {
    reporter_.SetMetricsLibraryInterface(NULL);
  }

  void DoInit();
  StrictMock<TaggedCounterMock>* tagged_counter_;
  TaggedCounterReporter reporter_;
  scoped_ptr<MetricsLibraryMock> metrics_lib_;
};

void TaggedCounterReporterTest::DoInit() {
  EXPECT_CALL(*tagged_counter_,
              Init(kTestFilename,
                   TaggedCounterReporter::Report,
                   &reporter_))
      .Times(1)
      .RetiresOnSaturation();
  reporter_.Init(kTestFilename,
                 kTestHistogram,
                 kHistogramMin,
                 kHistogramMax,
                 kHistogramBuckets);
  EXPECT_EQ(kTestHistogram, reporter_.histogram_name_);
  EXPECT_EQ(kHistogramBuckets, reporter_.buckets_);
  EXPECT_EQ(kHistogramMax, reporter_.max_);
  EXPECT_EQ(kHistogramMin, reporter_.min_);
}

TEST_F(TaggedCounterReporterTest, Init) {
  DoInit();
}

TEST_F(TaggedCounterReporterTest, Update) {
  DoInit();
  EXPECT_CALL(*tagged_counter_, Update(1, 2))
      .Times(1)
      .RetiresOnSaturation();
  reporter_.Update(1, 2);
}

TEST_F(TaggedCounterReporterTest, Flush) {
  DoInit();
  EXPECT_CALL(*tagged_counter_, Flush())
      .Times(1)
      .RetiresOnSaturation();
  reporter_.Flush();
}

TEST_F(TaggedCounterReporterTest, Report) {
  DoInit();
  EXPECT_CALL(*metrics_lib_, SendToUMA(kTestHistogram,
                                       301,
                                       kHistogramMin,
                                       kHistogramMax,
                                       kHistogramBuckets))
      .Times(1)
      .RetiresOnSaturation();
  reporter_.Report(&reporter_, 127, 301);
}

class FrequencyCounterTest : public testing::Test {
 protected:
  virtual void SetUp() {
    tagged_counter_ = NULL;
  }

  void CheckInit(int32 cycle_duration);
  void CheckCycleNumber(int32 cycle_duration);

  FrequencyCounter frequency_counter_;
  StrictMock<TaggedCounterMock>* tagged_counter_;

  TaggedCounter::Reporter reporter_;
};

void FrequencyCounterTest::CheckInit(int32 cycle_duration) {
  tagged_counter_ = new StrictMock<TaggedCounterMock>;
  frequency_counter_.Init(tagged_counter_, cycle_duration);
  EXPECT_EQ(cycle_duration, frequency_counter_.cycle_duration_);
  EXPECT_EQ(tagged_counter_, frequency_counter_.tagged_counter_.get());
}

TEST_F(FrequencyCounterTest, Init) {
  CheckInit(100);
}

void FrequencyCounterTest::CheckCycleNumber(int32 cycle_duration) {
  CheckInit(cycle_duration);
  EXPECT_EQ(150, frequency_counter_.GetCycleNumber(
      cycle_duration * 150));
  EXPECT_EQ(150, frequency_counter_.GetCycleNumber(
      cycle_duration * 150 + cycle_duration - 1));
  EXPECT_EQ(151, frequency_counter_.GetCycleNumber(
      cycle_duration * 151 + 1));
  EXPECT_EQ(0, frequency_counter_.GetCycleNumber(0));
}


TEST_F(FrequencyCounterTest, GetCycleNumberForWeek) {
  CheckCycleNumber(kSecondsPerWeek);
}

TEST_F(FrequencyCounterTest, GetCycleNumberForDay) {
  CheckCycleNumber(kSecondsPerDay);
}

TEST_F(FrequencyCounterTest, UpdateInternal) {
  CheckInit(kSecondsPerWeek);
  EXPECT_CALL(*tagged_counter_, Update(150, 2))
      .Times(1)
      .RetiresOnSaturation();
  frequency_counter_.UpdateInternal(2, kSecondsPerWeek * 150);
}

}  // namespace chromeos_metrics

int main(int argc, char** argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}

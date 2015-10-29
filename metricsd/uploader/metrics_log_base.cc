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

#include "uploader/metrics_log_base.h"

#include "base/build_time.h"
#include "base/metrics/histogram_base.h"
#include "base/metrics/histogram_samples.h"
#include "uploader/metrics_hashes.h"
#include "uploader/proto/histogram_event.pb.h"
#include "uploader/proto/system_profile.pb.h"
#include "uploader/proto/user_action_event.pb.h"

using base::Histogram;
using base::HistogramBase;
using base::HistogramSamples;
using base::SampleCountIterator;
using base::Time;
using base::TimeDelta;
using metrics::HistogramEventProto;
using metrics::SystemProfileProto;
using metrics::UserActionEventProto;

namespace metrics {
namespace {

// Any id less than 16 bytes is considered to be a testing id.
bool IsTestingID(const std::string& id) {
  return id.size() < 16;
}

}  // namespace

MetricsLogBase::MetricsLogBase(const std::string& client_id,
                               int session_id,
                               LogType log_type,
                               const std::string& version_string)
    : num_events_(0),
      locked_(false),
      log_type_(log_type) {
  DCHECK_NE(NO_LOG, log_type);
  if (IsTestingID(client_id))
    uma_proto_.set_client_id(0);
  else
    uma_proto_.set_client_id(Hash(client_id));

  uma_proto_.set_session_id(session_id);
  uma_proto_.mutable_system_profile()->set_build_timestamp(GetBuildTime());
  uma_proto_.mutable_system_profile()->set_app_version(version_string);
}

MetricsLogBase::~MetricsLogBase() {}

// static
uint64_t MetricsLogBase::Hash(const std::string& value) {
  uint64_t hash = metrics::HashMetricName(value);

  // The following log is VERY helpful when folks add some named histogram into
  // the code, but forgot to update the descriptive list of histograms.  When
  // that happens, all we get to see (server side) is a hash of the histogram
  // name.  We can then use this logging to find out what histogram name was
  // being hashed to a given MD5 value by just running the version of Chromium
  // in question with --enable-logging.
  VLOG(1) << "Metrics: Hash numeric [" << value << "]=[" << hash << "]";

  return hash;
}

// static
int64_t MetricsLogBase::GetBuildTime() {
  static int64_t integral_build_time = 0;
  if (!integral_build_time) {
    Time time = base::GetBuildTime();
    integral_build_time = static_cast<int64_t>(time.ToTimeT());
  }
  return integral_build_time;
}

// static
int64_t MetricsLogBase::GetCurrentTime() {
  return (base::TimeTicks::Now() - base::TimeTicks()).InSeconds();
}

void MetricsLogBase::CloseLog() {
  DCHECK(!locked_);
  locked_ = true;
}

void MetricsLogBase::GetEncodedLog(std::string* encoded_log) {
  DCHECK(locked_);
  uma_proto_.SerializeToString(encoded_log);
}

void MetricsLogBase::RecordUserAction(const std::string& key) {
  DCHECK(!locked_);

  UserActionEventProto* user_action = uma_proto_.add_user_action_event();
  user_action->set_name_hash(Hash(key));
  user_action->set_time(GetCurrentTime());

  ++num_events_;
}

void MetricsLogBase::RecordHistogramDelta(const std::string& histogram_name,
                                          const HistogramSamples& snapshot) {
  DCHECK(!locked_);
  DCHECK_NE(0, snapshot.TotalCount());

  // We will ignore the MAX_INT/infinite value in the last element of range[].

  HistogramEventProto* histogram_proto = uma_proto_.add_histogram_event();
  histogram_proto->set_name_hash(Hash(histogram_name));
  histogram_proto->set_sum(snapshot.sum());

  for (scoped_ptr<SampleCountIterator> it = snapshot.Iterator(); !it->Done();
       it->Next()) {
    HistogramBase::Sample min;
    HistogramBase::Sample max;
    HistogramBase::Count count;
    it->Get(&min, &max, &count);
    HistogramEventProto::Bucket* bucket = histogram_proto->add_bucket();
    bucket->set_min(min);
    bucket->set_max(max);
    bucket->set_count(count);
  }

  // Omit fields to save space (see rules in histogram_event.proto comments).
  for (int i = 0; i < histogram_proto->bucket_size(); ++i) {
    HistogramEventProto::Bucket* bucket = histogram_proto->mutable_bucket(i);
    if (i + 1 < histogram_proto->bucket_size() &&
        bucket->max() == histogram_proto->bucket(i + 1).min()) {
      bucket->clear_max();
    } else if (bucket->max() == bucket->min() + 1) {
      bucket->clear_min();
    }
  }
}

}  // namespace metrics

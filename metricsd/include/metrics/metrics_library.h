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

#ifndef METRICS_METRICS_LIBRARY_H_
#define METRICS_METRICS_LIBRARY_H_

#include <sys/types.h>
#include <string>
#include <unistd.h>

#include <base/compiler_specific.h>
#include <base/files/file_path.h>
#include <base/macros.h>
#include <binder/IServiceManager.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST

namespace android {
namespace brillo {
namespace metrics {
class IMetricsd;
}  // namespace metrics
}  // namespace brillo
}  // namespace android

class MetricsLibraryInterface {
 public:
  virtual void Init() = 0;
  virtual bool AreMetricsEnabled() = 0;
  virtual bool SendToUMA(const std::string& name, int sample,
                         int min, int max, int nbuckets) = 0;
  virtual bool SendEnumToUMA(const std::string& name, int sample, int max) = 0;
  virtual bool SendBoolToUMA(const std::string& name, bool sample) = 0;
  virtual bool SendSparseToUMA(const std::string& name, int sample) = 0;
  virtual ~MetricsLibraryInterface() {}
};

// Library used to send metrics to Chrome/UMA.
class MetricsLibrary : public MetricsLibraryInterface {
 public:
  MetricsLibrary();
  virtual ~MetricsLibrary();

  // Initializes the library.
  void Init() override;

  // Initializes the library and disables the cache of whether or not the
  // metrics collection is enabled.
  // By disabling this, we may have to check for the metrics status more often
  // but the result will never be stale.
  void InitWithNoCaching();

  // Returns whether or not the machine is running in guest mode.
  bool IsGuestMode();

  // Returns whether or not metrics collection is enabled.
  bool AreMetricsEnabled() override;

  // Sends histogram data to Chrome for transport to UMA and returns
  // true on success. This method results in the equivalent of an
  // asynchronous non-blocking RPC to UMA_HISTOGRAM_CUSTOM_COUNTS
  // inside Chrome (see base/histogram.h).
  //
  // |sample| is the sample value to be recorded (|min| <= |sample| < |max|).
  // |min| is the minimum value of the histogram samples (|min| > 0).
  // |max| is the maximum value of the histogram samples.
  // |nbuckets| is the number of histogram buckets.
  // [0,min) is the implicit underflow bucket.
  // [|max|,infinity) is the implicit overflow bucket.
  //
  // Note that the memory allocated in Chrome for each histogram is
  // proportional to the number of buckets. Therefore, it is strongly
  // recommended to keep this number low (e.g., 50 is normal, while
  // 100 is high).
  bool SendToUMA(const std::string& name, int sample,
                 int min, int max, int nbuckets) override;

  // Sends linear histogram data to Chrome for transport to UMA and
  // returns true on success. This method results in the equivalent of
  // an asynchronous non-blocking RPC to UMA_HISTOGRAM_ENUMERATION
  // inside Chrome (see base/histogram.h).
  //
  // |sample| is the sample value to be recorded (1 <= |sample| < |max|).
  // |max| is the maximum value of the histogram samples.
  // 0 is the implicit underflow bucket.
  // [|max|,infinity) is the implicit overflow bucket.
  //
  // An enumeration histogram requires |max| + 1 number of
  // buckets. Note that the memory allocated in Chrome for each
  // histogram is proportional to the number of buckets. Therefore, it
  // is strongly recommended to keep this number low (e.g., 50 is
  // normal, while 100 is high).
  bool SendEnumToUMA(const std::string& name, int sample, int max) override;

  // Specialization of SendEnumToUMA for boolean values.
  bool SendBoolToUMA(const std::string& name, bool sample) override;

  // Sends sparse histogram sample to Chrome for transport to UMA.  Returns
  // true on success.
  //
  // |sample| is the 32-bit integer value to be recorded.
  bool SendSparseToUMA(const std::string& name, int sample) override;

  // Sends a signal to UMA that a crash of the given |crash_kind|
  // has occurred.  Used by UMA to generate stability statistics.
  bool SendCrashToUMA(const char *crash_kind);

  // Sends a "generic Chrome OS event" to UMA.  This is an event name
  // that is translated into an enumerated histogram entry.  Event names
  // are added to metrics_library.cc.  Optionally, they can be added
  // to histograms.xml---but part of the reason for this is to simplify
  // the addition of events (at the cost of having to look them up by
  // number in the histograms dashboard).
  bool SendCrosEventToUMA(const std::string& event);

  // Debugging only.
  // Dumps the histograms aggregated since metricsd started into |dump|.
  // Returns true iff the dump succeeds.
  bool GetHistogramsDump(std::string* dump);

 private:
  friend class CMetricsLibraryTest;
  friend class MetricsLibraryTest;
  friend class UploadServiceTest;
  FRIEND_TEST(MetricsLibraryTest, AreMetricsEnabled);
  FRIEND_TEST(MetricsLibraryTest, AreMetricsEnabledNoCaching);
  FRIEND_TEST(MetricsLibraryTest, FormatChromeMessage);
  FRIEND_TEST(MetricsLibraryTest, FormatChromeMessageTooLong);
  FRIEND_TEST(MetricsLibraryTest, IsDeviceMounted);
  FRIEND_TEST(MetricsLibraryTest, SendMessageToChrome);
  FRIEND_TEST(MetricsLibraryTest, SendMessageToChromeUMAEventsBadFileLocation);

  void InitForTest(const base::FilePath& metrics_directory);

  // Sets |*result| to whether or not the |mounts_file| indicates that
  // the |device_name| is currently mounted.  Uses |buffer| of
  // |buffer_size| to read the file.  Returns false if any error.
  bool IsDeviceMounted(const char* device_name,
                       const char* mounts_file,
                       char* buffer, int buffer_size,
                       bool* result);

  // Connects to IMetricsd if the proxy does not exist or is not alive.
  // Don't block if we fail to get the proxy for any reason.
  bool CheckService();

  // Time at which we last checked if metrics were enabled.
  time_t cached_enabled_time_;

  // Cached state of whether or not metrics were enabled.
  bool cached_enabled_;

  // True iff we should cache the enabled/disabled status.
  bool use_caching_;

  android::sp<android::IServiceManager> manager_;
  android::sp<android::brillo::metrics::IMetricsd> metricsd_proxy_;
  base::FilePath consent_file_;

  DISALLOW_COPY_AND_ASSIGN(MetricsLibrary);
};

#endif  // METRICS_METRICS_LIBRARY_H_

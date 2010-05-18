// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef METRICS_LIBRARY_H_
#define METRICS_LIBRARY_H_

#include <sys/types.h>
#include <string>

#include <gtest/gtest_prod.h>  // for FRIEND_TEST

class MetricsLibraryInterface {
 public:
  virtual void Init() = 0;
  virtual bool SendToUMA(const std::string& name, int sample,
                         int min, int max, int nbuckets) = 0;
  virtual bool SendEnumToUMA(const std::string& name, int sample, int max) = 0;
  virtual ~MetricsLibraryInterface() {}
};

// Library used to send metrics to both Autotest and Chrome/UMA.
class MetricsLibrary : public MetricsLibraryInterface {
 public:
  MetricsLibrary();

  // Initializes the library.
  void Init();

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
  bool SendToUMA(const std::string& name, int sample,
                 int min, int max, int nbuckets);

  // Sends linear histogram data to Chrome for transport to UMA and
  // returns true on success. This method results in the equivalent of
  // an asynchronous non-blocking RPC to UMA_HISTOGRAM_ENUMERATION
  // inside Chrome (see base/histogram.h).
  //
  // |sample| is the sample value to be recorded (1 <= |sample| < |max|).
  // |max| is the maximum value of the histogram samples.
  // 0 is the implicit underflow bucket.
  // [|max|,infinity) is the implicit overflow bucket.
  bool SendEnumToUMA(const std::string& name, int sample, int max);

  // Sends to Autotest and returns true on success.
  static bool SendToAutotest(const std::string& name, int value);

 private:
  friend class MetricsLibraryTest;
  FRIEND_TEST(MetricsLibraryTest, FormatChromeMessage);
  FRIEND_TEST(MetricsLibraryTest, FormatChromeMessageTooLong);
  FRIEND_TEST(MetricsLibraryTest, SendMessageToChrome);
  FRIEND_TEST(MetricsLibraryTest, SendMessageToChromeUMAEventsBadFileLocation);

  // Sends message of size |length| to Chrome for transport to UMA and
  // returns true on success.
  bool SendMessageToChrome(int32_t length, const char* message);

  // Formats a name/value message for Chrome in |buffer| and returns the
  // length of the message or a negative value on error.
  //
  // Message format is: | LENGTH(binary) | NAME | \0 | VALUE | \0 |
  //
  // The arbitrary |format| argument covers the non-LENGTH portion of the
  // message. The caller is responsible to store the \0 character
  // between NAME and VALUE (e.g. "%s%c%d", name, '\0', value).
  int32_t FormatChromeMessage(int32_t buffer_size, char* buffer,
                              const char *format, ...);

  const char* uma_events_file_;
};

#endif /* METRICS_LIBRARY_H_ */

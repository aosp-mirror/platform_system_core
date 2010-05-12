// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef METRICS_LIBRARY_H_
#define METRICS_LIBRARY_H_

#include <string>

// TODO(sosa@chromium.org): Add testing for send methods

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
};

#endif /* METRICS_LIBRARY_H_ */

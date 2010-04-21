// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/*
 * metrics_library.h
 *
 *  Created on: Dec 1, 2009
 *      Author: sosa
 */

#ifndef METRICS_LIBRARY_H_
#define METRICS_LIBRARY_H_

#include <string>

// TODO(sosa@chromium.org): Add testing for send methods

// Library used to send metrics both Autotest and Chrome.
class MetricsLibrary {
 public:
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
  static bool SendToChrome(const std::string& name, int sample,
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
  static bool SendEnumToChrome(const std::string& name, int sample, int max);

  // Sends to Autotest and returns true on success.
  static bool SendToAutotest(const std::string& name, int value);
};

#endif /* METRICS_LIBRARY_H_ */

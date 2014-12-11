// Copyright 2014 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef METRICS_UPLOADER_METRICS_HASHES_H_
#define METRICS_UPLOADER_METRICS_HASHES_H_

#include <string>

namespace metrics {

// Computes a uint64 hash of a given string based on its MD5 hash. Suitable for
// metric names.
uint64_t HashMetricName(const std::string& name);

}  // namespace metrics

#endif  // METRICS_UPLOADER_METRICS_HASHES_H_

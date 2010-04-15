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

// Library used to send metrics both Autotest and Chrome
class MetricsLibrary {
 public:
  // Sends histogram data to Chrome and returns true on success.
  static bool SendToChrome(std::string name, int value);
  // Sends to Autotest and returns true on success.
  static bool SendToAutotest(std::string name, int value);
};

#endif /* METRICS_LIBRARY_H_ */

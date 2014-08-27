// Copyright 2014 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef METRICS_UPLOADER_SENDER_H_
#define METRICS_UPLOADER_SENDER_H_

#include <string>

// Abstract class for a Sender that uploads a metrics message.
class Sender {
 public:
  virtual ~Sender() {}
  // Sends a message |content| with its sha1 hash |hash|
  virtual bool Send(const std::string& content, const std::string& hash) = 0;
};

#endif  // METRICS_UPLOADER_SENDER_H_

// Copyright 2014 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef METRICS_UPLOADER_MOCK_SENDER_MOCK_H_
#define METRICS_UPLOADER_MOCK_SENDER_MOCK_H_

#include <string>

#include "base/compiler_specific.h"
#include "components/metrics/proto/chrome_user_metrics_extension.pb.h"
#include "uploader/sender.h"

class SenderMock : public Sender {
 public:
  SenderMock();

  bool Send(const std::string& content, const std::string& hash) override;
  void Reset();

  bool is_good_proto() { return is_good_proto_; }
  int send_call_count() { return send_call_count_; }
  const std::string last_message() { return last_message_; }
  metrics::ChromeUserMetricsExtension last_message_proto() {
    return last_message_proto_;
  }
  void set_should_succeed(bool succeed) { should_succeed_ = succeed; }

 private:
  // Is set to true if the proto was parsed successfully.
  bool is_good_proto_;

  // If set to true, the Send method will return true to simulate a successful
  // send.
  bool should_succeed_;

  // Count of how many times Send was called since the last reset.
  int send_call_count_;

  // Last message received by Send.
  std::string last_message_;

  // If is_good_proto is true, last_message_proto is the deserialized
  // representation of last_message.
  metrics::ChromeUserMetricsExtension last_message_proto_;
};

#endif  // METRICS_UPLOADER_MOCK_SENDER_MOCK_H_

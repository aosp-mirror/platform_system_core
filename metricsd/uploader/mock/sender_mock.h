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

#ifndef METRICS_UPLOADER_MOCK_SENDER_MOCK_H_
#define METRICS_UPLOADER_MOCK_SENDER_MOCK_H_

#include <string>

#include "base/compiler_specific.h"
#include "uploader/proto/chrome_user_metrics_extension.pb.h"
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

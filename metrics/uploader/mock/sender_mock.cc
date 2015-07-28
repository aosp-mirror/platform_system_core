// Copyright 2014 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "uploader/mock/sender_mock.h"

SenderMock::SenderMock() {
  Reset();
}

bool SenderMock::Send(const std::string& content, const std::string& hash) {
  send_call_count_ += 1;
  last_message_ = content;
  is_good_proto_ = last_message_proto_.ParseFromString(content);
  return should_succeed_;
}

void SenderMock::Reset() {
  send_call_count_ = 0;
  last_message_ = "";
  should_succeed_ = true;
  last_message_proto_.Clear();
  is_good_proto_ = false;
}

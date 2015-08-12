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

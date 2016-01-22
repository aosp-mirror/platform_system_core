/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include "event_log_list_builder.h"

#include <cinttypes>
#include <memory>
#include <string>
#include <android-base/logging.h>
#include <log/log.h>

namespace {

const size_t MAX_EVENT_PAYLOAD_SIZE = 512 - 1;  // Leave room for final '\n'.
const size_t EVENT_TYPE_SIZE = 1;  // Size in bytes of the event type marker.

}  // namespace

EventLogListBuilder::EventLogListBuilder()
    : payload_count_(0),
      payload_size_(0),
      payload_(std::make_unique<uint8_t[]>(MAX_EVENT_PAYLOAD_SIZE)) {
  memset(payload_.get(), 0, MAX_EVENT_PAYLOAD_SIZE);

  // Set up the top-level EventLog data type.
  AppendByte(EVENT_TYPE_LIST);

  // Skip over the byte prepresenting the number of items in the list. This
  // value is set in Release().
  payload_size_++;
}

bool EventLogListBuilder::Append(int value) {
  DCHECK_NE(static_cast<uint8_t*>(nullptr), payload_.get());

  if (!IsSpaceAvailable(sizeof(value) + EVENT_TYPE_SIZE)) {
    return false;
  }

  AppendByte(EVENT_TYPE_INT);
  AppendData(&value, sizeof(value));

  payload_count_++;
  return true;
}

bool EventLogListBuilder::Append(const std::string& value) {
  DCHECK_NE(static_cast<uint8_t*>(nullptr), payload_.get());

  int len = value.length();
  if (!IsSpaceAvailable(sizeof(len) + len)) {
    return false;
  }

  AppendByte(EVENT_TYPE_STRING);
  AppendData(&len, sizeof(len));
  AppendData(value.c_str(), len);

  payload_count_++;
  return true;
}

void EventLogListBuilder::Release(std::unique_ptr<uint8_t[]>* log,
                                  size_t* size) {
  // Finalize the log payload.
  payload_[1] = payload_count_;

  // Return the log payload.
  *size = payload_size_;
  *log = std::move(payload_);
}

void EventLogListBuilder::AppendData(const void* data, size_t size) {
  DCHECK_LT(payload_size_ + size, MAX_EVENT_PAYLOAD_SIZE);
  memcpy(&payload_[payload_size_], data, size);
  payload_size_ += size;
}

void EventLogListBuilder::AppendByte(uint8_t byte) {
  DCHECK_LT(payload_size_ + sizeof(byte), MAX_EVENT_PAYLOAD_SIZE);
  payload_[payload_size_++] = byte;
}

bool EventLogListBuilder::IsSpaceAvailable(size_t value_size) {
  size_t space_needed = value_size + EVENT_TYPE_SIZE;
  if (payload_size_ + space_needed > MAX_EVENT_PAYLOAD_SIZE) {
    size_t remaining = MAX_EVENT_PAYLOAD_SIZE - payload_size_;
    LOG(WARNING) << "Not enough space for value. remain=" <<
        remaining << "; needed=" << space_needed;
    return false;
  }

  return true;
}

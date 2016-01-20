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

#ifndef EVENT_LOG_LIST_BUILDER_H_
#define EVENT_LOG_LIST_BUILDER_H_

#include <cstdint>
#include <memory>

#include <android-base/macros.h>

// EventLogListBuilder provides a mechanism to build an EventLog list
// consisting of int and string EventLog values.
//
// NOTE: This class does not provide the ability to append an embedded list,
// i.e., a list containing a list.
class EventLogListBuilder {
 public:
  EventLogListBuilder();

  // Append a single value of a specified type.
  bool Append(int value);
  bool Append(const std::string& value);

  // Finalizes construction of the EventLog list and releases the data
  // to the caller. Caller takes ownership of the payload. No further calls
  // to append* may be made once the payload is acquired by the caller.
  void Release(std::unique_ptr<uint8_t[]>* log, size_t* size);

 private:
  // Appends |data| of the given |size| to the payload.
  void AppendData(const void* data, size_t size);

  // Appends a single byte to the payload.
  void AppendByte(uint8_t byte);

  // Returns true iff the remaining capacity in |payload_| is large enough to
  // accommodate |value_size| bytes. The space required to log the event type
  // is included in the internal calculation so must not be passed in to
  // |value_size|.
  bool IsSpaceAvailable(size_t value_size);

  // The number of items in the EventLog list.
  size_t payload_count_;

  // The size of the data stored in |payload_|. Used to track where to insert
  // new data.
  size_t payload_size_;

  // The payload constructed by calls to log*. The payload may only contain
  // MAX_EVENT_PAYLOAD (512) bytes.
  std::unique_ptr<uint8_t[]> payload_;

  DISALLOW_COPY_AND_ASSIGN(EventLogListBuilder);
};

 #endif  // EVENT_LOG_LIST_BUILDER_H_

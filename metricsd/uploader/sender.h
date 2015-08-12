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

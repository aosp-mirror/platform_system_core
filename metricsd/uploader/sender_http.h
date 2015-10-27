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

#ifndef METRICS_UPLOADER_SENDER_HTTP_H_
#define METRICS_UPLOADER_SENDER_HTTP_H_

#include <string>

#include <base/macros.h>

#include "uploader/sender.h"

// Sender implemented using http_utils from libbrillo
class HttpSender : public Sender {
 public:
  explicit HttpSender(std::string server_url);
  ~HttpSender() override = default;
  // Sends |content| whose SHA1 hash is |hash| to server_url with a synchronous
  // POST request to server_url.
  bool Send(const std::string& content, const std::string& hash) override;

 private:
  const std::string server_url_;

  DISALLOW_COPY_AND_ASSIGN(HttpSender);
};

#endif  // METRICS_UPLOADER_SENDER_HTTP_H_

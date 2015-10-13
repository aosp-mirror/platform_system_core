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

#include "uploader/sender_http.h"

#include <string>

#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <brillo/http/http_utils.h>
#include <brillo/mime_utils.h>

HttpSender::HttpSender(const std::string server_url)
    : server_url_(server_url) {}

bool HttpSender::Send(const std::string& content,
                      const std::string& content_hash) {
  const std::string hash =
      base::HexEncode(content_hash.data(), content_hash.size());

  brillo::http::HeaderList headers = {{"X-Chrome-UMA-Log-SHA1", hash}};
  brillo::ErrorPtr error;
  auto response = brillo::http::PostTextAndBlock(
      server_url_,
      content,
      brillo::mime::application::kWwwFormUrlEncoded,
      headers,
      brillo::http::Transport::CreateDefault(),
      &error);
  if (!response || response->ExtractDataAsString() != "OK") {
    if (error) {
      DLOG(ERROR) << "Failed to send data: " << error->GetMessage();
    }
    return false;
  }
  return true;
}

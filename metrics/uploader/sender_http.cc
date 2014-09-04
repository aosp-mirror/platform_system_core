// Copyright 2014 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "metrics/uploader/sender_http.h"

#include <string>

#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <chromeos/http/http_utils.h>
#include <chromeos/mime_utils.h>

HttpSender::HttpSender(const std::string server_url)
    : server_url_(server_url) {}

bool HttpSender::Send(const std::string& content,
                      const std::string& content_hash) {
  const std::string hash =
      base::HexEncode(content_hash.data(), content_hash.size());

  chromeos::http::HeaderList headers = {{"X-Chrome-UMA-Log-SHA1", hash}};
  chromeos::ErrorPtr error;
  auto response = chromeos::http::PostText(
      server_url_,
      content.c_str(),
      chromeos::mime::application::kWwwFormUrlEncoded,
      headers,
      chromeos::http::Transport::CreateDefault(),
      &error);
  if (!response || response->GetDataAsString() != "OK") {
    DLOG(ERROR) << "Failed to send data: " << error->GetMessage();
    return false;
  }
  return true;
}

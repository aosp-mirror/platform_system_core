// Copyright 2014 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "uploader/curl_sender.h"

#include <curl/curl.h>
#include <string>

#include "base/logging.h"
#include "base/strings/string_number_conversions.h"

CurlSender::CurlSender(const std::string server_url)
    : server_url_(server_url) {}

bool CurlSender::Send(const std::string& content,
                      const std::string& content_hash) {
  CURL* postrequest = curl_easy_init();

  if (!postrequest) {
    DLOG(ERROR) << "Error creating the post request";
    return false;
  }

  curl_easy_setopt(postrequest, CURLOPT_URL, server_url_.c_str());
  curl_easy_setopt(postrequest, CURLOPT_POST, 1);

  const std::string hash =
      base::HexEncode(content_hash.data(), content_hash.size());

  curl_slist* headers =
      curl_slist_append(nullptr, ("X-Chrome-UMA-Log-SHA1: " + hash).c_str());
  if (!headers) {
    DLOG(ERROR) << "failed setting the headers";
    curl_easy_cleanup(postrequest);
    return false;
  }

  std::string output;

  curl_easy_setopt(postrequest, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(postrequest, CURLOPT_POSTFIELDSIZE, content.size());
  curl_easy_setopt(postrequest, CURLOPT_POSTFIELDS, content.c_str());

  // Set the callback function used to read the response and the destination.
  curl_easy_setopt(postrequest, CURLOPT_WRITEFUNCTION, ReadData);
  curl_easy_setopt(postrequest, CURLOPT_WRITEDATA, &output);

  CURLcode result = curl_easy_perform(postrequest);

  if (result == CURLE_OK && output == "OK") {
    curl_easy_cleanup(postrequest);
    return true;
  }

  curl_easy_cleanup(postrequest);

  return false;
}

// static
size_t CurlSender::ReadData(void* buffer, size_t size, size_t nmember,
                            std::string* out) {
  CHECK(out);

  // This function might be called several time so we want to append the data at
  // the end of the string.
  *out += std::string(static_cast<char*>(buffer), size * nmember);
  return size * nmember;
}

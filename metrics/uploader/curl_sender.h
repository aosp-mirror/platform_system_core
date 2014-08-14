// Copyright 2014 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef METRICS_UPLOADER_CURL_SENDER_H_
#define METRICS_UPLOADER_CURL_SENDER_H_

#include <string>

#include "base/compiler_specific.h"
#include "uploader/sender.h"

// Sender implemented using libcurl
class CurlSender : public Sender {
 public:
  explicit CurlSender(std::string server_url);

  // Sends |content| whose SHA1 hash is |hash| to server_url with a synchronous
  // POST request to server_url.
  bool Send(const std::string& content, const std::string& hash) override;

  // Static callback required by curl to retrieve the response data.
  //
  // Copies |size| * |nmember| bytes of data from |buffer| to |out|.
  // Returns the number of bytes copied.
  static size_t ReadData(void* buffer, size_t size, size_t nmember,
                         std::string* out);

 private:
  const std::string server_url_;
};

#endif  // METRICS_UPLOADER_CURL_SENDER_H_

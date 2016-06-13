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

#include "trusty_nvram_implementation.h"

#include <errno.h>
#include <string.h>

#include <hardware/nvram.h>
#include <trusty/tipc.h>

#define LOG_TAG "TrustyNVRAM"
#include <log/log.h>

#include <nvram/messages/blob.h>

namespace nvram {
namespace {

// Character device to open for Trusty IPC connections.
const char kTrustyDeviceName[] = "/dev/trusty-ipc-dev0";

// App identifier of the NVRAM app.
const char kTrustyNvramAppId[] = "com.android.trusty.nvram";

}  // namespace

TrustyNvramImplementation::~TrustyNvramImplementation() {
  if (tipc_nvram_fd_ != -1) {
    tipc_close(tipc_nvram_fd_);
    tipc_nvram_fd_ = -1;
  }
}

void TrustyNvramImplementation::Execute(const nvram::Request& request,
                                        nvram::Response* response) {
  if (!SendRequest(request, response)) {
    response->result = NV_RESULT_INTERNAL_ERROR;
  }
}

bool TrustyNvramImplementation::Connect() {
  if (tipc_nvram_fd_ != -1) {
    return true;
  }

  int rc = tipc_connect(kTrustyDeviceName, kTrustyNvramAppId);
  if (rc < 0) {
    ALOGE("Failed to connect to Trusty NVRAM app: %s\n", strerror(-rc));
    return false;
  }

  tipc_nvram_fd_ = rc;
  return true;
}

bool TrustyNvramImplementation::SendRequest(const nvram::Request& request,
                                            nvram::Response* response) {
  if (!Connect()) {
    return false;
  }

  nvram::Blob request_buffer;
  if (!nvram::Encode(request, &request_buffer)) {
    ALOGE("Failed to encode NVRAM request.\n");
    return false;
  }

  ssize_t rc =
      write(tipc_nvram_fd_, request_buffer.data(), request_buffer.size());
  if (rc < 0) {
    ALOGE("Failed to send NVRAM request: %s\n", strerror(-rc));
    return false;
  }
  if (static_cast<size_t>(rc) != request_buffer.size()) {
    ALOGE("Failed to send full request buffer: %zd\n", rc);
    return false;
  }

  rc = read(tipc_nvram_fd_, response_buffer_, sizeof(response_buffer_));
  if (rc < 0) {
    ALOGE("Failed to read NVRAM response: %s\n", strerror(-rc));
    return false;
  }

  if (static_cast<size_t>(rc) >= sizeof(response_buffer_)) {
    ALOGE("NVRAM response exceeds response buffer size.\n");
    return false;
  }

  if (!nvram::Decode(response_buffer_, static_cast<size_t>(rc), response)) {
    ALOGE("Failed to decode NVRAM response.\n");
    return false;
  }

  return true;
}

}  // namespace nvram

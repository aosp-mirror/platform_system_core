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

#include <errno.h>
#include <string.h>

#include <hardware/nvram.h>
#include <trusty/tipc.h>

#define LOG_TAG "TrustyNVRAM"
#include <log/log.h>

#include <nvram/hal/nvram_device_adapter.h>
#include <nvram/messages/blob.h>
#include <nvram/messages/nvram_messages.h>

namespace {

// Character device to open for Trusty IPC connections.
const char kTrustyDeviceName[] = "/dev/trusty-ipc-dev0";

// App identifier of the NVRAM app.
const char kTrustyNvramAppId[] = "com.android.trusty.nvram";

// |TrustyNvramImplementation| proxies requests to the Trusty NVRAM app. It
// serializes the request objects, sends it to the Trusty app and finally reads
// back the result and decodes it.
class TrustyNvramImplementation : public nvram::NvramImplementation {
 public:
  ~TrustyNvramImplementation() override;

  void Execute(const nvram::Request& request,
               nvram::Response* response) override;

 private:
  // Connects the IPC channel to the Trusty app if it is not already open.
  // Returns true if the channel is open, false on errors.
  bool Connect();

  // Dispatches a command to the trust app. Returns true if successful (note
  // that the response may still indicate an error on the Trusty side), false if
  // there are any I/O or encoding/decoding errors.
  bool SendRequest(const nvram::Request& request,
                   nvram::Response* response);

  // The file descriptor for the IPC connection to the Trusty app.
  int tipc_nvram_fd_ = -1;

  // Response buffer. This puts a hard size limit on the responses from the
  // Trusty app. 4096 matches the maximum IPC message size currently supported
  // by Trusty.
  uint8_t response_buffer_[4096];
};

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

}  // namespace

extern "C" int trusty_nvram_open(const hw_module_t* module,
                                 const char* device_id,
                                 hw_device_t** device_ptr) {
  if (strcmp(NVRAM_HARDWARE_DEVICE_ID, device_id) != 0) {
    return -EINVAL;
  }

  nvram::NvramDeviceAdapter* adapter =
      new nvram::NvramDeviceAdapter(module, new TrustyNvramImplementation);
  *device_ptr = adapter->as_device();
  return 0;
}

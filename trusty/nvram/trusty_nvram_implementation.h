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

#ifndef TRUSTY_NVRAM_TRUSTY_NVRAM_IMPLEMENTATION_H_
#define TRUSTY_NVRAM_TRUSTY_NVRAM_IMPLEMENTATION_H_

#include <stdint.h>

#include <nvram/hal/nvram_device_adapter.h>
#include <nvram/messages/nvram_messages.h>

namespace nvram {

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

}  // namespace nvram

#endif  // TRUSTY_NVRAM_TRUSTY_NVRAM_IMPLEMENTATION_H_

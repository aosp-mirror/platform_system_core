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

#pragma once

#include <android-base/macros.h>

// General interface to allow the fastboot protocol to be used over different
// types of transports.
class Transport {
  public:
    Transport() = default;
    virtual ~Transport() = default;

    // Reads |len| bytes into |data|. Returns the number of bytes actually
    // read or -1 on error.
    virtual ssize_t Read(void* data, size_t len) = 0;

    // Writes |len| bytes from |data|. Returns the number of bytes actually
    // written or -1 on error.
    virtual ssize_t Write(const void* data, size_t len) = 0;

    // Closes the underlying transport. Returns 0 on success.
    virtual int Close() = 0;

    virtual int Reset() = 0;

    // Blocks until the transport disconnects. Transports that don't support
    // this will return immediately. Returns 0 on success.
    virtual int WaitForDisconnect() { return 0; }

  private:
    DISALLOW_COPY_AND_ASSIGN(Transport);
};

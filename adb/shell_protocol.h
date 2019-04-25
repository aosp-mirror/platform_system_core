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

#include <stdint.h>

#include <android-base/macros.h>

#include "adb.h"

// Class to send and receive shell protocol packets.
//
// To keep things simple and predictable, reads and writes block until an entire
// packet is complete.
//
// Example: read raw data from |fd| and send it in a packet.
//   ShellProtocol* p = new ShellProtocol(protocol_fd);
//   int len = adb_read(stdout_fd, p->data(), p->data_capacity());
//   packet->WritePacket(ShellProtocol::kIdStdout, len);
//
// Example: read a packet and print it to |stdout|.
//   ShellProtocol* p = new ShellProtocol(protocol_fd);
//   if (p->ReadPacket() && p->id() == kIdStdout) {
//       fwrite(p->data(), 1, p->data_length(), stdout);
//   }
class ShellProtocol {
  public:
    // This is an unscoped enum to make it easier to compare against raw bytes.
    enum Id : uint8_t {
        kIdStdin = 0,
        kIdStdout = 1,
        kIdStderr = 2,
        kIdExit = 3,

        // Close subprocess stdin if possible.
        kIdCloseStdin = 4,

        // Window size change (an ASCII version of struct winsize).
        kIdWindowSizeChange = 5,

        // Indicates an invalid or unknown packet.
        kIdInvalid = 255,
    };

    // ShellPackets will probably be too large to allocate on the stack so they
    // should be dynamically allocated on the heap instead.
    //
    // |fd| is an open file descriptor to be used to send or receive packets.
    explicit ShellProtocol(int fd);
    virtual ~ShellProtocol();

    // Returns a pointer to the data buffer.
    const char* data() const { return buffer_ + kHeaderSize; }
    char* data() { return buffer_ + kHeaderSize; }

    // Returns the total capacity of the data buffer.
    size_t data_capacity() const { return buffer_end_ - data(); }

    // Reads a packet from the FD.
    //
    // If a packet is too big to fit in the buffer then Read() will split the
    // packet across multiple calls. For example, reading a 50-byte packet into
    // a 20-byte buffer would read 20 bytes, 20 bytes, then 10 bytes.
    //
    // Returns false if the FD closed or errored.
    bool Read();

    // Returns the ID of the packet in the buffer.
    int id() const { return buffer_[0]; }

    // Returns the number of bytes that have been read into the data buffer.
    size_t data_length() const { return data_length_; }

    // Writes the packet currently in the buffer to the FD.
    //
    // Returns false if the FD closed or errored.
    bool Write(Id id, size_t length);

  private:
    // Packets support 4-byte lengths.
    typedef uint32_t length_t;

    enum {
        // It's OK if MAX_PAYLOAD doesn't match on the sending and receiving
        // end, reading will split larger packets into multiple smaller ones.
        kBufferSize = MAX_PAYLOAD,

        // Header is 1 byte ID + 4 bytes length.
        kHeaderSize = sizeof(Id) + sizeof(length_t)
    };

    int fd_;
    char buffer_[kBufferSize];
    size_t data_length_ = 0, bytes_left_ = 0;

    // We need to be able to modify this value for testing purposes, but it
    // will stay constant during actual program use.
    char* buffer_end_ = buffer_ + sizeof(buffer_);

    friend class ShellProtocolTest;

    DISALLOW_COPY_AND_ASSIGN(ShellProtocol);
};

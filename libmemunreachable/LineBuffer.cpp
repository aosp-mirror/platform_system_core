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

// Copied from system/extras/memory_replay/LineBuffer.cpp
// TODO(ccross): find a way to share between libmemunreachable and memory_replay?

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "LineBuffer.h"

namespace android {

LineBuffer::LineBuffer(int fd, char* buffer, size_t buffer_len)
    : fd_(fd), buffer_(buffer), buffer_len_(buffer_len) {}

bool LineBuffer::GetLine(char** line, size_t* line_len) {
  while (true) {
    if (bytes_ > 0) {
      char* newline = reinterpret_cast<char*>(memchr(buffer_ + start_, '\n', bytes_));
      if (newline != nullptr) {
        *newline = '\0';
        *line = buffer_ + start_;
        start_ = newline - buffer_ + 1;
        bytes_ -= newline - *line + 1;
        *line_len = newline - *line;
        return true;
      }
    }
    if (start_ > 0) {
      // Didn't find anything, copy the current to the front of the buffer.
      memmove(buffer_, buffer_ + start_, bytes_);
      start_ = 0;
    }
    ssize_t bytes = TEMP_FAILURE_RETRY(read(fd_, buffer_ + bytes_, buffer_len_ - bytes_ - 1));
    if (bytes <= 0) {
      if (bytes_ > 0) {
        // The read data might not contain a nul terminator, so add one.
        buffer_[bytes_] = '\0';
        *line = buffer_ + start_;
        *line_len = bytes_;
        bytes_ = 0;
        start_ = 0;
        return true;
      }
      return false;
    }
    bytes_ += bytes;
  }
}

}  // namespace android

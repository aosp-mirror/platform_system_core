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

#ifndef _LIBMEMUNREACHABLE_LINE_BUFFER_H
#define _LIBMEMUNREACHABLE_LINE_BUFFER_H

#include <stdint.h>

namespace android {

class LineBuffer {
 public:
  LineBuffer(int fd, char* buffer, size_t buffer_len);

  bool GetLine(char** line, size_t* line_len);

 private:
  int fd_;
  char* buffer_ = nullptr;
  size_t buffer_len_ = 0;
  size_t start_ = 0;
  size_t bytes_ = 0;
};

}  // namespace android

#endif  // _LIBMEMUNREACHABLE_LINE_BUFFER_H

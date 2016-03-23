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

#ifndef ANDROID_BASE_UNIQUE_FD_H
#define ANDROID_BASE_UNIQUE_FD_H

#include <unistd.h>

#include <android-base/macros.h>

/* Container for a file descriptor that automatically closes the descriptor as
 * it goes out of scope.
 *
 *      unique_fd ufd(open("/some/path", "r"));
 *
 *      if (ufd.get() < 0) // invalid descriptor
 *          return error;
 *
 *      // Do something useful
 *
 *      return 0; // descriptor is closed here
 */
namespace android {
namespace base {

class unique_fd final {
 public:
  unique_fd() : value_(-1) {}

  explicit unique_fd(int value) : value_(value) {}
  ~unique_fd() { clear(); }

  unique_fd(unique_fd&& other) : value_(other.release()) {}
  unique_fd& operator = (unique_fd&& s) {
    reset(s.release());
    return *this;
  }

  void reset(int new_value) {
    if (value_ >= 0)
      close(value_);
    value_ = new_value;
  }

  void clear() {
    reset(-1);
  }

  int get() const { return value_; }

  int release() {
    int ret = value_;
    value_ = -1;
    return ret;
  }

 private:
  int value_;

  DISALLOW_COPY_AND_ASSIGN(unique_fd);
};

}  // namespace base
}  // namespace android

#endif  // ANDROID_BASE_UNIQUE_FD_H

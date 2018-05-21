/*
 * Copyright (C) 2017 The Android Open Source Project
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

#ifndef PROPERTY_INFO_SERIALIZER_SPACE_TOKENIZER_H
#define PROPERTY_INFO_SERIALIZER_SPACE_TOKENIZER_H

namespace android {
namespace properties {

class SpaceTokenizer {
 public:
  SpaceTokenizer(const std::string& string)
      : string_(string), it_(string_.begin()), end_(string_.end()) {}

  std::string GetNext() {
    auto next = std::string();
    while (it_ != end_ && !isspace(*it_)) {
      next.push_back(*it_++);
    }
    while (it_ != end_ && isspace(*it_)) {
      it_++;
    }
    return next;
  }

  std::string GetRemaining() { return std::string(it_, end_); }

 private:
  std::string string_;
  std::string::const_iterator it_;
  std::string::const_iterator end_;
};

}  // namespace properties
}  // namespace android

#endif

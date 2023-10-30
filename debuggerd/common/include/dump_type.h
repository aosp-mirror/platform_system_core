#pragma once

/*
 * Copyright 2017, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <sys/types.h>

#include <ostream>

enum DebuggerdDumpType : uint8_t {
  kDebuggerdNativeBacktrace,
  kDebuggerdTombstone,
  kDebuggerdJavaBacktrace,
  kDebuggerdAnyIntercept,
  kDebuggerdTombstoneProto,
};

inline const char* get_dump_type_name(const DebuggerdDumpType& dump_type) {
  switch (dump_type) {
    case kDebuggerdNativeBacktrace:
      return "kDebuggerdNativeBacktrace";
    case kDebuggerdTombstone:
      return "kDebuggerdTombstone";
    case kDebuggerdJavaBacktrace:
      return "kDebuggerdJavaBacktrace";
    case kDebuggerdAnyIntercept:
      return "kDebuggerdAnyIntercept";
    case kDebuggerdTombstoneProto:
      return "kDebuggerdTombstoneProto";
    default:
      return "[unknown]";
  }
}

inline std::ostream& operator<<(std::ostream& stream, const DebuggerdDumpType& rhs) {
  stream << get_dump_type_name(rhs);
  return stream;
}

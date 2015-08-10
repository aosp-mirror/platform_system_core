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

#include "uploader/metrics_hashes.h"

#include "base/logging.h"
#include "base/md5.h"
#include "base/sys_byteorder.h"

namespace metrics {

namespace {

// Converts the 8-byte prefix of an MD5 hash into a uint64 value.
inline uint64_t HashToUInt64(const std::string& hash) {
  uint64_t value;
  DCHECK_GE(hash.size(), sizeof(value));
  memcpy(&value, hash.data(), sizeof(value));
  return base::HostToNet64(value);
}

}  // namespace

uint64_t HashMetricName(const std::string& name) {
  // Create an MD5 hash of the given |name|, represented as a byte buffer
  // encoded as an std::string.
  base::MD5Context context;
  base::MD5Init(&context);
  base::MD5Update(&context, name);

  base::MD5Digest digest;
  base::MD5Final(&digest, &context);

  std::string hash_str(reinterpret_cast<char*>(digest.a), arraysize(digest.a));
  return HashToUInt64(hash_str);
}

}  // namespace metrics

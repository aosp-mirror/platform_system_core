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

#include <cstdint>
#include <string>

namespace android {
namespace metricslogger {

// Logs a Tron histogram metric named |event| containing |data| to the Tron log
// buffer.
void LogHistogram(const std::string& event, int32_t data);

// TODO: replace these with the metric_logger.proto definitions
enum {
  LOGBUILDER_CATEGORY = 757,
  LOGBUILDER_NAME = 799,
  LOGBUILDER_BUCKET = 801,
  LOGBUILDER_VALUE = 802,
  LOGBUILDER_HISTOGRAM = 804,
};

}  // namespace metricslogger
}  // namespace android

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

#include "histogram_logger.h"

#include <cstdlib>
#include <memory>
#include <android-base/logging.h>
#include <log/log.h>
#include "event_log_list_builder.h"

namespace bootstat {

void LogHistogram(const std::string& event, int32_t data) {
  LOG(INFO) << "Logging histogram: " << event << " " << data;

  EventLogListBuilder log_builder;
  log_builder.Append(event);
  log_builder.Append(data);

  std::unique_ptr<uint8_t[]> log;
  size_t size;
  log_builder.Release(&log, &size);

  android_bWriteLog(HISTOGRAM_LOG_TAG, log.get(), size);
}

}  // namespace bootstat
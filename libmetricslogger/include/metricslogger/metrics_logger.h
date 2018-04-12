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

#include <log/log_event_list.h>
#include <cstdint>
#include <string>

namespace android {
namespace metricslogger {

// Logs a Tron histogram metric named |event| containing |data| to the Tron log
// buffer.
void LogHistogram(const std::string& event, int32_t data);

// Logs a Tron counter metric named |name| containing |val| count to the Tron
// log buffer.
void LogCounter(const std::string& name, int32_t val);

// Logs a Tron multi_action with category|category| containing the string
// |value| in the field |field|.
void LogMultiAction(int32_t category, int32_t field, const std::string& value);

// Logs a Tron complex event.
//
// A complex event can include data in a structure not suppored by the other
// log event types above.
//
// Note that instances of this class are single use. You must call Record()
// to write the event to the event log.
class ComplexEventLogger {
  private:
    android_log_event_list logger;

  public:
    // Create a complex event with category|category|.
    explicit ComplexEventLogger(int category);
    // Add tagged data to the event, with the given tag and integer value.
    void AddTaggedData(int tag, int32_t value);
    // Add tagged data to the event, with the given tag and string value.
    void AddTaggedData(int tag, const std::string& value);
    // Add tagged data to the event, with the given tag and integer value.
    void AddTaggedData(int tag, int64_t value);
    // Add tagged data to the event, with the given tag and float value.
    void AddTaggedData(int tag, float value);
    // Record this event. This method can only be used once per instance
    // of ComplexEventLogger. Do not made any subsequent calls to AddTaggedData
    // after recording an event.
    void Record();
};

// TODO: replace these with the metric_logger.proto definitions
enum {
    LOGBUILDER_CATEGORY = 757,
    LOGBUILDER_TYPE = 758,
    LOGBUILDER_NAME = 799,
    LOGBUILDER_BUCKET = 801,
    LOGBUILDER_VALUE = 802,
    LOGBUILDER_COUNTER = 803,
    LOGBUILDER_HISTOGRAM = 804,

    ACTION_BOOT = 1098,
    FIELD_PLATFORM_REASON = 1099,

    ACTION_HIDDEN_API_ACCESSED = 1391,
    FIELD_HIDDEN_API_ACCESS_METHOD = 1392,
    FIELD_HIDDEN_API_ACCESS_DENIED = 1393,
    FIELD_HIDDEN_API_SIGNATURE = 1394,
};

enum {
    TYPE_ACTION = 4,
};

enum {
    ACCESS_METHOD_NONE = 0,
    ACCESS_METHOD_REFLECTION = 1,
    ACCESS_METHOD_JNI = 2,
    ACCESS_METHOD_LINKING = 3,
};

}  // namespace metricslogger
}  // namespace android

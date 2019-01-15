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
#include <stats_event_list.h>
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
    stats_event_list stats_logger;

  public:
    // Create a complex event with category|category|.
    explicit ComplexEventLogger(int category);
    // Set the package name that this event originates from.
    void SetPackageName(const std::string& package_name);
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
    LOGBUILDER_PACKAGENAME = 806,

    ACTION_BOOT = 1098,
    FIELD_PLATFORM_REASON = 1099,

    FIELD_DURATION_MILLIS = 1304,

    FIELD_END_BATTERY_PERCENT = 1308,

    ACTION_HIDDEN_API_ACCESSED = 1391,
    FIELD_HIDDEN_API_ACCESS_METHOD = 1392,
    FIELD_HIDDEN_API_ACCESS_DENIED = 1393,
    FIELD_HIDDEN_API_SIGNATURE = 1394,

    ACTION_USB_CONNECTOR_CONNECTED = 1422,
    ACTION_USB_CONNECTOR_DISCONNECTED = 1423,
    ACTION_USB_AUDIO_CONNECTED = 1424,
    FIELD_USB_AUDIO_VIDPID = 1425,
    ACTION_USB_AUDIO_DISCONNECTED = 1426,
    ACTION_HARDWARE_FAILED = 1427,
    FIELD_HARDWARE_TYPE = 1428,
    FIELD_HARDWARE_FAILURE_CODE = 1429,
    ACTION_PHYSICAL_DROP = 1430,
    FIELD_CONFIDENCE_PERCENT = 1431,
    FIELD_ACCEL_MILLI_G = 1432,
    ACTION_BATTERY_HEALTH = 1433,
    FIELD_BATTERY_HEALTH_SNAPSHOT_TYPE = 1434,
    FIELD_BATTERY_TEMPERATURE_DECI_C = 1435,
    FIELD_BATTERY_VOLTAGE_UV = 1436,
    FIELD_BATTERY_OPEN_CIRCUIT_VOLTAGE_UV = 1437,
    ACTION_BATTERY_CHARGE_CYCLES = 1438,
    FIELD_BATTERY_CHARGE_CYCLES = 1439,

    ACTION_SLOW_IO = 1442,
    FIELD_IO_OPERATION_TYPE = 1443,
    FIELD_IO_OPERATION_COUNT = 1444,
    ACTION_SPEAKER_IMPEDANCE = 1445,
    FIELD_SPEAKER_IMPEDANCE_MILLIOHMS = 1446,
    FIELD_SPEAKER_LOCATION = 1447,
    FIELD_BATTERY_RESISTANCE_UOHMS = 1448,
    FIELD_BATTERY_CURRENT_UA = 1449,
    FIELD_HARDWARE_LOCATION = 1450,
    ACTION_BATTERY_CAUSED_SHUTDOWN = 1451,
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

enum HardwareType {
    HARDWARE_UNKNOWN = 0,
    HARDWARE_MICROPHONE = 1,
    HARDWARE_CODEC = 2,
    HARDWARE_SPEAKER = 3,
    HARDWARE_FINGERPRINT = 4,
};

enum HardwareFailureCode {
    HARDWARE_FAILURE_UNKNOWN = 0,
    HARDWARE_FAILURE_COMPLETE = 1,
    HARDWARE_FAILURE_SPEAKER_HIGH_Z = 2,
    HARDWARE_FAILURE_SPEAKER_SHORT = 3,
    HARDWARE_FAILURE_FINGERPRINT_SENSOR_BROKEN = 4,
    HARDWARE_FAILURE_FINGERPRINT_TOO_MANY_DEAD_PIXELS = 5,
};

enum IoOperation {
    IOOP_UNKNOWN = 0,
    IOOP_READ = 1,
    IOOP_WRITE = 2,
    IOOP_UNMAP = 3,
    IOOP_SYNC = 4,
};

}  // namespace metricslogger
}  // namespace android

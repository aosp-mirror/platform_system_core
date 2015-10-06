# Copyright (C) 2015 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

LOCAL_PATH := $(call my-dir)

metrics_cpp_extension := .cc
libmetrics_sources := \
  c_metrics_library.cc \
  metrics_library.cc \
  serialization/metric_sample.cc \
  serialization/serialization_utils.cc \
  timer.cc

metrics_client_sources := \
  metrics_client.cc

metrics_daemon_common := \
  collectors/averaged_statistics_collector.cc \
  collectors/disk_usage_collector.cc \
  metrics_daemon.cc \
  persistent_integer.cc \
  serialization/metric_sample.cc \
  serialization/serialization_utils.cc \
  uploader/metrics_hashes.cc \
  uploader/metrics_log_base.cc \
  uploader/metrics_log.cc \
  uploader/sender_http.cc \
  uploader/system_profile_cache.cc \
  uploader/upload_service.cc \

metrics_tests_sources := \
  collectors/averaged_statistics_collector_test.cc \
  metrics_daemon_test.cc \
  metrics_library_test.cc \
  persistent_integer_test.cc \
  serialization/serialization_utils_unittest.cc \
  timer_test.cc \
  uploader/metrics_hashes_unittest.cc \
  uploader/metrics_log_base_unittest.cc \
  uploader/mock/sender_mock.cc \
  uploader/upload_service_test.cc \

metrics_CFLAGS := -Wall \
  -Wno-char-subscripts \
  -Wno-missing-field-initializers \
  -Wno-unused-function \
  -Wno-unused-parameter \
  -Werror \
  -fvisibility=default
metrics_CPPFLAGS := -Wno-non-virtual-dtor \
  -Wno-sign-promo \
  -Wno-strict-aliasing \
  -fvisibility=default
metrics_includes := external/gtest/include \
  $(LOCAL_PATH)/include
libmetrics_shared_libraries := libchrome libchromeos
metrics_daemon_shared_libraries := $(libmetrics_shared_libraries) \
  libchrome-dbus \
  libchromeos-http \
  libchromeos-dbus \
  libcutils \
  libdbus \
  libmetrics \
  libprotobuf-cpp-lite \
  librootdev \
  libweaved-client \

# Shared library for metrics.
# ========================================================
include $(CLEAR_VARS)
LOCAL_MODULE := libmetrics
LOCAL_C_INCLUDES := $(metrics_includes)
LOCAL_CFLAGS := $(metrics_CFLAGS)
LOCAL_CLANG := true
LOCAL_CPP_EXTENSION := $(metrics_cpp_extension)
LOCAL_CPPFLAGS := $(metrics_CPPFLAGS)
LOCAL_RTTI_FLAG := -frtti
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/include
LOCAL_SHARED_LIBRARIES := $(libmetrics_shared_libraries)
LOCAL_SRC_FILES := $(libmetrics_sources)
include $(BUILD_SHARED_LIBRARY)

# CLI client for metrics.
# ========================================================
include $(CLEAR_VARS)
LOCAL_MODULE := metrics_client
LOCAL_C_INCLUDES := $(metrics_includes)
LOCAL_CFLAGS := $(metrics_CFLAGS)
LOCAL_CLANG := true
LOCAL_CPP_EXTENSION := $(metrics_cpp_extension)
LOCAL_CPPFLAGS := $(metrics_CPPFLAGS)
LOCAL_SHARED_LIBRARIES := $(libmetrics_shared_libraries) \
  libmetrics
LOCAL_SRC_FILES := $(metrics_client_sources)
include $(BUILD_EXECUTABLE)

# Protobuf library for metrics_daemon.
# ========================================================
include $(CLEAR_VARS)
LOCAL_MODULE := metrics_daemon_protos
LOCAL_MODULE_CLASS := STATIC_LIBRARIES
generated_sources_dir := $(call local-generated-sources-dir)
LOCAL_EXPORT_C_INCLUDE_DIRS += \
    $(generated_sources_dir)/proto/system/core/metricsd
LOCAL_SRC_FILES :=  $(call all-proto-files-under,uploader/proto)
include $(BUILD_STATIC_LIBRARY)

# metrics daemon.
# ========================================================
include $(CLEAR_VARS)
LOCAL_MODULE := metrics_daemon
LOCAL_C_INCLUDES := $(metrics_includes) \
  external/libchromeos
LOCAL_CFLAGS := $(metrics_CFLAGS)
LOCAL_CPP_EXTENSION := $(metrics_cpp_extension)
LOCAL_CPPFLAGS := $(metrics_CPPFLAGS)
LOCAL_INIT_RC := metrics_daemon.rc
LOCAL_REQUIRED_MODULES := \
  metrics.json \
  metrics.schema.json \

LOCAL_RTTI_FLAG := -frtti
LOCAL_SHARED_LIBRARIES := $(metrics_daemon_shared_libraries)
LOCAL_CLANG := true
LOCAL_SRC_FILES := $(metrics_daemon_common) \
  metrics_daemon_main.cc
LOCAL_STATIC_LIBRARIES := metrics_daemon_protos
include $(BUILD_EXECUTABLE)

# Unit tests for metrics.
# ========================================================
include $(CLEAR_VARS)
LOCAL_MODULE := metrics_tests
LOCAL_CLANG := true
LOCAL_CFLAGS := $(metrics_CFLAGS)
LOCAL_CPP_EXTENSION := $(metrics_cpp_extension)
LOCAL_CPPFLAGS := $(metrics_CPPFLAGS) -Wno-sign-compare
LOCAL_RTTI_FLAG := -frtti
LOCAL_SHARED_LIBRARIES := $(metrics_daemon_shared_libraries)
LOCAL_SRC_FILES := $(metrics_tests_sources) $(metrics_daemon_common)
LOCAL_STATIC_LIBRARIES := libBionicGtestMain libgmock metrics_daemon_protos

include $(BUILD_NATIVE_TEST)

# Weave schema files
# ========================================================
include $(CLEAR_VARS)
LOCAL_MODULE := metrics.json
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(TARGET_OUT_ETC)/weaved/commands
LOCAL_SRC_FILES := etc/weaved/commands/$(LOCAL_MODULE)
include $(BUILD_PREBUILT)

include $(CLEAR_VARS)
LOCAL_MODULE := metrics.schema.json
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(TARGET_OUT_ETC)/weaved/states
LOCAL_SRC_FILES := etc/weaved/states/$(LOCAL_MODULE)
include $(BUILD_PREBUILT)

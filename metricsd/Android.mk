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
  timer.cc

metrics_client_sources := \
  metrics_client.cc

metrics_collector_common := \
  collectors/averaged_statistics_collector.cc \
  collectors/cpu_usage_collector.cc \
  collectors/disk_usage_collector.cc \
  metrics_collector.cc \
  metrics_collector_service_impl.cc \
  persistent_integer.cc

metricsd_common := \
  persistent_integer.cc \
  uploader/bn_metricsd_impl.cc \
  uploader/crash_counters.cc \
  uploader/metrics_hashes.cc \
  uploader/metrics_log_base.cc \
  uploader/metrics_log.cc \
  uploader/metricsd_service_runner.cc \
  uploader/sender_http.cc \
  uploader/system_profile_cache.cc \
  uploader/upload_service.cc

metrics_collector_tests_sources := \
  collectors/averaged_statistics_collector_test.cc \
  collectors/cpu_usage_collector_test.cc \
  metrics_collector_test.cc \
  metrics_library_test.cc \
  persistent_integer_test.cc \
  timer_test.cc

metricsd_tests_sources := \
  uploader/metrics_hashes_unittest.cc \
  uploader/metrics_log_base_unittest.cc \
  uploader/mock/sender_mock.cc \
  uploader/upload_service_test.cc

metrics_CFLAGS := -Wall \
  -Wno-char-subscripts \
  -Wno-missing-field-initializers \
  -Wno-unused-parameter \
  -Werror \
  -fvisibility=default
metrics_CPPFLAGS := -Wno-non-virtual-dtor \
  -Wno-sign-promo \
  -Wno-strict-aliasing \
  -fvisibility=default
metrics_includes := external/gtest/include \
  $(LOCAL_PATH)/include
libmetrics_shared_libraries := libchrome libbinder libbrillo libutils
metrics_collector_shared_libraries := $(libmetrics_shared_libraries) \
  libbrillo-binder \
  libbrillo-http \
  libmetrics \
  librootdev \
  libweaved

metrics_collector_static_libraries := libmetricscollectorservice

metricsd_shared_libraries := \
  libbinder \
  libbrillo \
  libbrillo-binder \
  libbrillo-http \
  libchrome \
  libprotobuf-cpp-lite \
  libupdate_engine_client \
  libutils

# Static proxy library for the metricsd binder interface.
# ========================================================
include $(CLEAR_VARS)
LOCAL_MODULE := metricsd_binder_proxy
LOCAL_SHARED_LIBRARIES := libbinder libutils
LOCAL_SRC_FILES := aidl/android/brillo/metrics/IMetricsd.aidl
include $(BUILD_STATIC_LIBRARY)

# Static library for the metrics_collector binder interface.
# ==========================================================
include $(CLEAR_VARS)
LOCAL_MODULE := libmetricscollectorservice
LOCAL_CLANG := true
LOCAL_SHARED_LIBRARIES := libbinder libbrillo-binder libchrome libutils
LOCAL_CPP_EXTENSION := $(metrics_cpp_extension)
LOCAL_C_INCLUDES := $(LOCAL_PATH)/include
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/include
LOCAL_SRC_FILES := \
  aidl/android/brillo/metrics/IMetricsCollectorService.aidl \
  metrics_collector_service_client.cc
include $(BUILD_STATIC_LIBRARY)

# Shared library for metrics.
# ========================================================
include $(CLEAR_VARS)
LOCAL_MODULE := libmetrics
LOCAL_C_INCLUDES := $(metrics_includes)
LOCAL_CFLAGS := $(metrics_CFLAGS)
LOCAL_CLANG := true
LOCAL_CPP_EXTENSION := $(metrics_cpp_extension)
LOCAL_CPPFLAGS := $(metrics_CPPFLAGS)
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/include
LOCAL_SHARED_LIBRARIES := $(libmetrics_shared_libraries)
LOCAL_SRC_FILES := $(libmetrics_sources)
LOCAL_STATIC_LIBRARIES := metricsd_binder_proxy
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
LOCAL_STATIC_LIBRARIES := metricsd_binder_proxy
include $(BUILD_EXECUTABLE)

# Protobuf library for metricsd.
# ========================================================
include $(CLEAR_VARS)
LOCAL_MODULE := metricsd_protos
LOCAL_MODULE_CLASS := STATIC_LIBRARIES
generated_sources_dir := $(call local-generated-sources-dir)
LOCAL_EXPORT_C_INCLUDE_DIRS += \
    $(generated_sources_dir)/proto/system/core/metricsd
LOCAL_SRC_FILES :=  $(call all-proto-files-under,uploader/proto)
include $(BUILD_STATIC_LIBRARY)

# metrics_collector daemon.
# ========================================================
include $(CLEAR_VARS)
LOCAL_MODULE := metrics_collector
LOCAL_C_INCLUDES := $(metrics_includes)
LOCAL_CFLAGS := $(metrics_CFLAGS)
LOCAL_CLANG := true
LOCAL_CPP_EXTENSION := $(metrics_cpp_extension)
LOCAL_CPPFLAGS := $(metrics_CPPFLAGS)
LOCAL_INIT_RC := metrics_collector.rc
LOCAL_REQUIRED_MODULES := metrics.json
LOCAL_SHARED_LIBRARIES := $(metrics_collector_shared_libraries)
LOCAL_SRC_FILES := $(metrics_collector_common) \
  metrics_collector_main.cc
LOCAL_STATIC_LIBRARIES := metricsd_binder_proxy \
  $(metrics_collector_static_libraries)
include $(BUILD_EXECUTABLE)

# metricsd daemon.
# ========================================================
include $(CLEAR_VARS)
LOCAL_MODULE := metricsd
LOCAL_C_INCLUDES := $(metrics_includes)
LOCAL_CFLAGS := $(metrics_CFLAGS)
LOCAL_CLANG := true
LOCAL_CPP_EXTENSION := $(metrics_cpp_extension)
LOCAL_CPPFLAGS := $(metrics_CPPFLAGS)
LOCAL_INIT_RC := metricsd.rc
LOCAL_REQUIRED_MODULES := \
  metrics_collector
LOCAL_SHARED_LIBRARIES := $(metricsd_shared_libraries)
LOCAL_STATIC_LIBRARIES := metricsd_protos metricsd_binder_proxy
LOCAL_SRC_FILES := $(metricsd_common) \
  metricsd_main.cc
include $(BUILD_EXECUTABLE)

# Unit tests for metricsd.
# ========================================================
include $(CLEAR_VARS)
LOCAL_MODULE := metricsd_tests
LOCAL_CFLAGS := $(metrics_CFLAGS)
LOCAL_CLANG := true
LOCAL_CPP_EXTENSION := $(metrics_cpp_extension)
LOCAL_CPPFLAGS := $(metrics_CPPFLAGS) -Wno-sign-compare
LOCAL_SHARED_LIBRARIES := $(metricsd_shared_libraries)
LOCAL_SRC_FILES := $(metricsd_tests_sources) $(metricsd_common)
LOCAL_STATIC_LIBRARIES := libBionicGtestMain libgmock metricsd_protos metricsd_binder_proxy
ifdef BRILLO
LOCAL_MODULE_TAGS := eng
endif
include $(BUILD_NATIVE_TEST)

# Unit tests for metrics_collector.
# ========================================================
include $(CLEAR_VARS)
LOCAL_MODULE := metrics_collector_tests
LOCAL_CFLAGS := $(metrics_CFLAGS)
LOCAL_CLANG := true
LOCAL_CPP_EXTENSION := $(metrics_cpp_extension)
LOCAL_CPPFLAGS := $(metrics_CPPFLAGS) -Wno-sign-compare
LOCAL_SHARED_LIBRARIES := $(metrics_collector_shared_libraries)
LOCAL_SRC_FILES := $(metrics_collector_tests_sources) \
  $(metrics_collector_common)
LOCAL_STATIC_LIBRARIES := libBionicGtestMain libgmock metricsd_binder_proxy \
  $(metrics_collector_static_libraries)
ifdef BRILLO
LOCAL_MODULE_TAGS := eng
endif
include $(BUILD_NATIVE_TEST)

# Weave schema files
# ========================================================
include $(CLEAR_VARS)
LOCAL_MODULE := metrics.json
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(TARGET_OUT_ETC)/weaved/traits
LOCAL_SRC_FILES := etc/weaved/traits/$(LOCAL_MODULE)
include $(BUILD_PREBUILT)

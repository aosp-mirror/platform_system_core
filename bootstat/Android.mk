#
# Copyright (C) 2016 The Android Open Source Project
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
#

LOCAL_PATH := $(call my-dir)

bootstat_c_includes := external/gtest/include

bootstat_lib_src_files := \
        boot_event_record_store.cpp \
        event_log_list_builder.cpp \
        histogram_logger.cpp \
        uptime_parser.cpp \

bootstat_src_files := \
        bootstat.cpp \

bootstat_test_src_files := \
        boot_event_record_store_test.cpp \
        event_log_list_builder_test.cpp \
        testrunner.cpp \

bootstat_shared_libs := \
        libbase \
        libcutils \
        liblog \

bootstat_cflags := \
        -Wall \
        -Wextra \
        -Werror \

# 524291 corresponds to sysui_histogram, from
# frameworks/base/core/java/com/android/internal/logging/EventLogTags.logtags
bootstat_cflags += -DHISTOGRAM_LOG_TAG=524291

bootstat_debug_cflags := \
        $(bootstat_cflags) \
        -UNDEBUG \

# bootstat static library
# -----------------------------------------------------------------------------

include $(CLEAR_VARS)

LOCAL_MODULE := libbootstat
LOCAL_CFLAGS := $(bootstat_cflags)
LOCAL_C_INCLUDES := $(bootstat_c_includes)
LOCAL_SHARED_LIBRARIES := $(bootstat_shared_libs)
LOCAL_SRC_FILES := $(bootstat_lib_src_files)
# Clang is required because of C++14
LOCAL_CLANG := true

include $(BUILD_STATIC_LIBRARY)

# bootstat static library, debug
# -----------------------------------------------------------------------------

include $(CLEAR_VARS)

LOCAL_MODULE := libbootstat_debug
LOCAL_CFLAGS := $(bootstat_cflags)
LOCAL_C_INCLUDES := $(bootstat_c_includes)
LOCAL_SHARED_LIBRARIES := $(bootstat_shared_libs)
LOCAL_SRC_FILES := $(bootstat_lib_src_files)
# Clang is required because of C++14
LOCAL_CLANG := true

include $(BUILD_STATIC_LIBRARY)

# bootstat host static library, debug
# -----------------------------------------------------------------------------

include $(CLEAR_VARS)

LOCAL_MODULE := libbootstat_host_debug
LOCAL_CFLAGS := $(bootstat_debug_cflags)
LOCAL_C_INCLUDES := $(bootstat_c_includes)
LOCAL_SHARED_LIBRARIES := $(bootstat_shared_libs)
LOCAL_SRC_FILES := $(bootstat_lib_src_files)
# Clang is required because of C++14
LOCAL_CLANG := true

include $(BUILD_HOST_STATIC_LIBRARY)

# bootstat binary
# -----------------------------------------------------------------------------

include $(CLEAR_VARS)

LOCAL_MODULE := bootstat
LOCAL_CFLAGS := $(bootstat_cflags)
LOCAL_C_INCLUDES := $(bootstat_c_includes)
LOCAL_SHARED_LIBRARIES := $(bootstat_shared_libs)
LOCAL_STATIC_LIBRARIES := libbootstat
LOCAL_INIT_RC := bootstat.rc
LOCAL_SRC_FILES := $(bootstat_src_files)
# Clang is required because of C++14
LOCAL_CLANG := true

include $(BUILD_EXECUTABLE)

# Native tests
# -----------------------------------------------------------------------------

include $(CLEAR_VARS)

LOCAL_MODULE := bootstat_tests
LOCAL_CFLAGS := $(bootstat_tests_cflags)
LOCAL_SHARED_LIBRARIES := $(bootstat_shared_libs)
LOCAL_STATIC_LIBRARIES := libbootstat_debug libgmock
LOCAL_SRC_FILES := $(bootstat_test_src_files)
# Clang is required because of C++14
LOCAL_CLANG := true

include $(BUILD_NATIVE_TEST)

# Host native tests
# -----------------------------------------------------------------------------

include $(CLEAR_VARS)

LOCAL_MODULE := bootstat_tests
LOCAL_CFLAGS := $(bootstat_tests_cflags)
LOCAL_SHARED_LIBRARIES := $(bootstat_shared_libs)
LOCAL_STATIC_LIBRARIES := libbootstat_host_debug libgmock_host
LOCAL_SRC_FILES := $(bootstat_test_src_files)
# Clang is required because of C++14
LOCAL_CLANG := true

include $(BUILD_HOST_NATIVE_TEST)

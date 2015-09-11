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

ifeq ($(HOST_OS),linux)

crash_reporter_cpp_extension := .cc

crash_reporter_src := crash_collector.cc \
    kernel_collector.cc \
    kernel_warning_collector.cc \
    udev_collector.cc \
    unclean_shutdown_collector.cc \
    user_collector.cc

crash_reporter_includes := external/gtest/include

crash_reporter_test_src := crash_collector_test.cc \
    crash_reporter_logs_test.cc \
    kernel_collector_test.cc \
    testrunner.cc \
    udev_collector_test.cc \
    unclean_shutdown_collector_test.cc \
    user_collector_test.cc

warn_collector_src := warn_collector.l

# Crash reporter static library.
# ========================================================
include $(CLEAR_VARS)
LOCAL_MODULE := libcrash
LOCAL_CPP_EXTENSION := $(crash_reporter_cpp_extension)
LOCAL_C_INCLUDES := $(crash_reporter_includes)
LOCAL_RTTI_FLAG := -frtti
LOCAL_SHARED_LIBRARIES := libchrome \
    libchromeos \
    libcutils \
    libdbus \
    libmetrics \
    libpcrecpp
LOCAL_SRC_FILES := $(crash_reporter_src)
include $(BUILD_STATIC_LIBRARY)

# Crash reporter client.
# ========================================================
include $(CLEAR_VARS)
LOCAL_MODULE := crash_reporter
LOCAL_CPP_EXTENSION := $(crash_reporter_cpp_extension)
LOCAL_C_INCLUDES := $(crash_reporter_includes)
LOCAL_REQUIRED_MODULES := core2md \
    crash_reporter_logs.conf \
    crash_sender \
    dbus-send \
    init.crash_reporter.rc
LOCAL_RTTI_FLAG := -frtti
LOCAL_SHARED_LIBRARIES := libchrome \
    libchromeos \
    libcutils \
    libdbus \
    libmetrics \
    libpcrecpp
LOCAL_SRC_FILES := crash_reporter.cc
LOCAL_STATIC_LIBRARIES := libcrash
include $(BUILD_EXECUTABLE)

# Crash sender script.
# ========================================================
include $(CLEAR_VARS)
LOCAL_MODULE := crash_sender
LOCAL_MODULE_CLASS := EXECUTABLES
LOCAL_MODULE_PATH := $(TARGET_OUT_EXECUTABLES)
LOCAL_REQUIRED_MODULES := curl periodic_scheduler
LOCAL_SRC_FILES := crash_sender
include $(BUILD_PREBUILT)

# Warn collector client.
# ========================================================
include $(CLEAR_VARS)
LOCAL_MODULE := warn_collector
LOCAL_CPP_EXTENSION := $(crash_reporter_cpp_extension)
LOCAL_SHARED_LIBRARIES := libmetrics
LOCAL_SRC_FILES := $(warn_collector_src)
include $(BUILD_EXECUTABLE)

# Crash reporter init script.
# ========================================================
ifdef TARGET_COPY_OUT_INITRCD
include $(CLEAR_VARS)
LOCAL_MODULE := init.crash_reporter.rc
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(PRODUCT_OUT)/$(TARGET_COPY_OUT_INITRCD)
LOCAL_SRC_FILES := init.crash_reporter.rc
include $(BUILD_PREBUILT)
endif

# Crash reporter logs conf file.
# ========================================================
include $(CLEAR_VARS)
LOCAL_MODULE := crash_reporter_logs.conf
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(PRODUCT_OUT)/system/etc
LOCAL_SRC_FILES := crash_reporter_logs.conf
include $(BUILD_PREBUILT)

# Periodic Scheduler.
# ========================================================
include $(CLEAR_VARS)
LOCAL_MODULE := periodic_scheduler
LOCAL_MODULE_CLASS := EXECUTABLES
LOCAL_MODULE_PATH := $(TARGET_OUT_EXECUTABLES)
LOCAL_SRC_FILES := periodic_scheduler
include $(BUILD_PREBUILT)

# Crash reporter tests.
# ========================================================
include $(CLEAR_VARS)
LOCAL_MODULE := crash_reporter_tests
LOCAL_CPP_EXTENSION := $(crash_reporter_cpp_extension)
LOCAL_SHARED_LIBRARIES := libchrome \
    libchromeos \
    libdbus \
    libpcrecpp
LOCAL_SRC_FILES := $(crash_reporter_test_src)
LOCAL_STATIC_LIBRARIES := libcrash libgmock
include $(BUILD_NATIVE_TEST)

endif # HOST_OS == linux

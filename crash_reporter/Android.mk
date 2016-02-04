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

crash_reporter_cpp_extension := .cc

crash_reporter_src := crash_collector.cc \
    kernel_collector.cc \
    kernel_warning_collector.cc \
    unclean_shutdown_collector.cc \
    user_collector.cc

crash_reporter_includes := external/gtest/include

crash_reporter_test_src := crash_collector_test.cc \
    crash_reporter_logs_test.cc \
    kernel_collector_test.cc \
    testrunner.cc \
    unclean_shutdown_collector_test.cc \
    user_collector_test.cc

warn_collector_src := warn_collector.l

# Crash reporter static library.
# ========================================================
include $(CLEAR_VARS)
LOCAL_MODULE := libcrash
LOCAL_CPP_EXTENSION := $(crash_reporter_cpp_extension)
LOCAL_C_INCLUDES := $(crash_reporter_includes)
LOCAL_SHARED_LIBRARIES := libchrome \
    libbinder \
    libbrillo \
    libcutils \
    libmetrics \
    libpcrecpp
LOCAL_STATIC_LIBRARIES := libmetricscollectorservice
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
    crash_server
LOCAL_INIT_RC := crash_reporter.rc
LOCAL_SHARED_LIBRARIES := libchrome \
    libbinder \
    libbrillo \
    libcutils \
    libmetrics \
    libpcrecpp \
    libutils
LOCAL_SRC_FILES := crash_reporter.cc
LOCAL_STATIC_LIBRARIES := libcrash \
    libmetricscollectorservice
include $(BUILD_EXECUTABLE)

# Crash sender script.
# ========================================================
include $(CLEAR_VARS)
LOCAL_MODULE := crash_sender
LOCAL_MODULE_CLASS := EXECUTABLES
LOCAL_MODULE_PATH := $(TARGET_OUT_EXECUTABLES)
LOCAL_REQUIRED_MODULES := curl grep periodic_scheduler
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

# /etc/os-release.d/crash_server configuration file.
# ========================================================
ifdef OSRELEASED_DIRECTORY
include $(CLEAR_VARS)
LOCAL_MODULE := crash_server
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(TARGET_OUT_ETC)/$(OSRELEASED_DIRECTORY)
include $(BUILD_SYSTEM)/base_rules.mk

# Optionally populate the BRILLO_CRASH_SERVER variable from a product
# configuration file: brillo/crash_server.
LOADED_BRILLO_CRASH_SERVER := $(call cfgtree-get-if-exists,brillo/crash_server)

# If the crash server isn't set, use a blank value.  crash_sender
# will log it as a configuration error.
$(LOCAL_BUILT_MODULE): BRILLO_CRASH_SERVER ?= "$(LOADED_BRILLO_CRASH_SERVER)"
$(LOCAL_BUILT_MODULE):
	$(hide)mkdir -p $(dir $@)
	echo $(BRILLO_CRASH_SERVER) > $@
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
ifdef BRILLO
LOCAL_MODULE_TAGS := eng
endif
LOCAL_SHARED_LIBRARIES := libchrome \
    libbrillo \
    libcutils \
    libpcrecpp
LOCAL_SRC_FILES := $(crash_reporter_test_src)
LOCAL_STATIC_LIBRARIES := libcrash libgmock
include $(BUILD_NATIVE_TEST)

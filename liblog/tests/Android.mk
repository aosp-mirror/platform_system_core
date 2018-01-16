#
# Copyright (C) 2013-2014 The Android Open Source Project
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

# -----------------------------------------------------------------------------
# Benchmarks.
# -----------------------------------------------------------------------------

test_module_prefix := liblog-
test_tags := tests

benchmark_c_flags := \
    -Wall \
    -Wextra \
    -Werror \
    -fno-builtin \

benchmark_src_files := \
    liblog_benchmark.cpp

# Build benchmarks for the device. Run with:
#   adb shell liblog-benchmarks
include $(CLEAR_VARS)
LOCAL_MODULE := $(test_module_prefix)benchmarks
LOCAL_MODULE_TAGS := $(test_tags)
LOCAL_CFLAGS += $(benchmark_c_flags)
LOCAL_SHARED_LIBRARIES += liblog libm libbase
LOCAL_SRC_FILES := $(benchmark_src_files)
include $(BUILD_NATIVE_BENCHMARK)

# -----------------------------------------------------------------------------
# Unit tests.
# -----------------------------------------------------------------------------

test_c_flags := \
    -fstack-protector-all \
    -g \
    -Wall -Wextra \
    -Werror \
    -fno-builtin \

cts_src_files := \
    libc_test.cpp \
    liblog_test_default.cpp \
    liblog_test_local.cpp \
    liblog_test_stderr.cpp \
    liblog_test_stderr_local.cpp \
    log_id_test.cpp \
    log_radio_test.cpp \
    log_read_test.cpp \
    log_system_test.cpp \
    log_time_test.cpp \
    log_wrap_test.cpp

test_src_files := \
    $(cts_src_files) \

# Build tests for the device (with .so). Run with:
#   adb shell /data/nativetest/liblog-unit-tests/liblog-unit-tests
include $(CLEAR_VARS)
LOCAL_MODULE := $(test_module_prefix)unit-tests
LOCAL_MODULE_TAGS := $(test_tags)
LOCAL_CFLAGS += $(test_c_flags)
LOCAL_SHARED_LIBRARIES := liblog libcutils libbase
LOCAL_SRC_FILES := $(test_src_files)
include $(BUILD_NATIVE_TEST)

cts_executable := CtsLiblogTestCases

include $(CLEAR_VARS)
LOCAL_MODULE := $(cts_executable)
LOCAL_MODULE_TAGS := tests
LOCAL_CFLAGS += $(test_c_flags) -DNO_PSTORE
LOCAL_SRC_FILES := $(cts_src_files)
LOCAL_MODULE_PATH := $(TARGET_OUT_DATA)/nativetest
LOCAL_MULTILIB := both
LOCAL_MODULE_STEM_32 := $(LOCAL_MODULE)32
LOCAL_MODULE_STEM_64 := $(LOCAL_MODULE)64
LOCAL_SHARED_LIBRARIES := liblog libcutils libbase
LOCAL_STATIC_LIBRARIES := libgtest libgtest_main
LOCAL_COMPATIBILITY_SUITE := cts vts
LOCAL_CTS_TEST_PACKAGE := android.core.liblog
include $(BUILD_CTS_EXECUTABLE)

ifeq ($(HOST_OS)-$(HOST_ARCH),$(filter $(HOST_OS)-$(HOST_ARCH),linux-x86 linux-x86_64))

include $(CLEAR_VARS)
LOCAL_MODULE := $(cts_executable)_list
LOCAL_MODULE_TAGS := optional
LOCAL_CFLAGS := $(test_c_flags) -DHOST
LOCAL_C_INCLUDES := external/gtest/include
LOCAL_SRC_FILES := $(test_src_files)
LOCAL_MULTILIB := both
LOCAL_MODULE_STEM_32 := $(LOCAL_MODULE)
LOCAL_MODULE_STEM_64 := $(LOCAL_MODULE)64
LOCAL_CXX_STL := libc++
LOCAL_SHARED_LIBRARIES := liblog libcutils libbase
LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
LOCAL_LDLIBS_linux := -lrt
include $(BUILD_HOST_NATIVE_TEST)

endif  # ifeq ($(HOST_OS)-$(HOST_ARCH),$(filter $(HOST_OS)-$(HOST_ARCH),linux-x86 linux-x86_64))

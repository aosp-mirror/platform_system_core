#
# Copyright (C) 2014 The Android Open Source Project
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
# Benchmarks. (see ../../liblog/tests)
# -----------------------------------------------------------------------------

test_module_prefix := logd-
test_tags := tests

# -----------------------------------------------------------------------------
# Unit tests.
# -----------------------------------------------------------------------------

event_flag := -DAUDITD_LOG_TAG=1003 -DCHATTY_LOG_TAG=1004

test_c_flags := \
    -fstack-protector-all \
    -g \
    -Wall -Wextra \
    -Werror \
    -fno-builtin \
    $(event_flag)

test_src_files := \
    logd_test.cpp

# Build tests for the logger. Run with:
#   adb shell /data/nativetest/logd-unit-tests/logd-unit-tests
include $(CLEAR_VARS)
LOCAL_MODULE := $(test_module_prefix)unit-tests
LOCAL_MODULE_TAGS := $(test_tags)
LOCAL_CFLAGS += $(test_c_flags)
LOCAL_SHARED_LIBRARIES := libbase libcutils liblog libselinux
LOCAL_SRC_FILES := $(test_src_files)
include $(BUILD_NATIVE_TEST)

cts_executable := CtsLogdTestCases

include $(CLEAR_VARS)
LOCAL_MODULE := $(cts_executable)
LOCAL_MODULE_TAGS := tests
LOCAL_CFLAGS += $(test_c_flags)
LOCAL_SRC_FILES := $(test_src_files)
LOCAL_MODULE_PATH := $(TARGET_OUT_DATA)/nativetest
LOCAL_MULTILIB := both
LOCAL_MODULE_STEM_32 := $(LOCAL_MODULE)32
LOCAL_MODULE_STEM_64 := $(LOCAL_MODULE)64
LOCAL_SHARED_LIBRARIES := libbase libcutils liblog libselinux
LOCAL_STATIC_LIBRARIES := libgtest libgtest_main
LOCAL_COMPATIBILITY_SUITE := cts vts
LOCAL_CTS_TEST_PACKAGE := android.core.logd
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
LOCAL_SHARED_LIBRARIES := libbase libcutils liblog
LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
include $(BUILD_HOST_NATIVE_TEST)

endif  # ifeq ($(HOST_OS)-$(HOST_ARCH),$(filter $(HOST_OS)-$(HOST_ARCH),linux-x86 linux-x86_64))

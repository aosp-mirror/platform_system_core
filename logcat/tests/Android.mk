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
# Unit tests.
# -----------------------------------------------------------------------------

test_module := logcat-unit-tests
test_tags := tests

test_c_flags := \
    -fstack-protector-all \
    -g \
    -Wall -Wextra \
    -Werror \
    -fno-builtin

test_src_files := \
    logcat_test.cpp \

# Build tests for the device (with .so). Run with:
#   adb shell /data/nativetest/logcat-unit-tests/logcat-unit-tests
include $(CLEAR_VARS)
LOCAL_MODULE := $(test_module)
LOCAL_MODULE_TAGS := $(test_tags)
LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
LOCAL_CFLAGS += $(test_c_flags)
LOCAL_SHARED_LIBRARIES := liblog
LOCAL_SRC_FILES := $(test_src_files)
include $(BUILD_NATIVE_TEST)

#
# Copyright 2014 The Android Open Source Project
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

LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)
LOCAL_CLANG := true
LOCAL_MODULE := sync-unit-tests
LOCAL_CFLAGS += -g -Wall -Werror -std=gnu++11 -Wno-missing-field-initializers -Wno-sign-compare
LOCAL_SHARED_LIBRARIES += libsync
LOCAL_STATIC_LIBRARIES += libgtest_main
LOCAL_C_INCLUDES += $(LOCAL_PATH)/../include
LOCAL_C_INCLUDES += $(LOCAL_PATH)/..
LOCAL_SRC_FILES := \
    sync_test.cpp
include $(BUILD_NATIVE_TEST)

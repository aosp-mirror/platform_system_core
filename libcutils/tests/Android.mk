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

LOCAL_PATH := $(call my-dir)

test_src_files := \
    MemsetTest.cpp \
    PropertiesTest.cpp \

include $(CLEAR_VARS)
LOCAL_MODULE := libcutils_test
LOCAL_SRC_FILES := $(test_src_files)
LOCAL_SHARED_LIBRARIES := \
    libcutils \
    liblog \
    libutils \

LOCAL_MULTILIB := both
LOCAL_MODULE_STEM_32 := $(LOCAL_MODULE)32
LOCAL_MODULE_STEM_64 := $(LOCAL_MODULE)64
include $(BUILD_NATIVE_TEST)

include $(CLEAR_VARS)
LOCAL_MODULE := libcutils_test_static
LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_SRC_FILES := $(test_src_files)
LOCAL_STATIC_LIBRARIES := \
    libc \
    libcutils \
    liblog \
    libstlport_static \
    libutils \

LOCAL_MULTILIB := both
LOCAL_MODULE_STEM_32 := $(LOCAL_MODULE)32
LOCAL_MODULE_STEM_64 := $(LOCAL_MODULE)64
include $(BUILD_NATIVE_TEST)

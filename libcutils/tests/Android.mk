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
    sockets_test.cpp \

test_src_files_nonwindows := \
    test_str_parms.cpp \

test_target_only_src_files := \
    MemsetTest.cpp \
    PropertiesTest.cpp \
    trace-dev_test.cpp \

test_libraries := libcutils liblog libbase


#
# Target.
#

include $(CLEAR_VARS)
LOCAL_MODULE := libcutils_test
LOCAL_SRC_FILES := $(test_src_files) $(test_target_only_src_files)
LOCAL_SHARED_LIBRARIES := $(test_libraries)
LOCAL_MULTILIB := both
LOCAL_MODULE_STEM_32 := $(LOCAL_MODULE)32
LOCAL_MODULE_STEM_64 := $(LOCAL_MODULE)64
include $(BUILD_NATIVE_TEST)

include $(CLEAR_VARS)
LOCAL_MODULE := libcutils_test_static
LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_SRC_FILES := $(test_src_files) $(test_target_only_src_files)
LOCAL_STATIC_LIBRARIES := libc $(test_libraries)
LOCAL_CXX_STL := libc++_static
LOCAL_MULTILIB := both
LOCAL_MODULE_STEM_32 := $(LOCAL_MODULE)32
LOCAL_MODULE_STEM_64 := $(LOCAL_MODULE)64
include $(BUILD_NATIVE_TEST)


#
# Host.
#

include $(CLEAR_VARS)
LOCAL_MODULE := libcutils_test
LOCAL_SRC_FILES := $(test_src_files) $(test_src_files_nonwindows)
LOCAL_SHARED_LIBRARIES := $(test_libraries)
LOCAL_MULTILIB := both
LOCAL_MODULE_STEM_32 := $(LOCAL_MODULE)32
LOCAL_MODULE_STEM_64 := $(LOCAL_MODULE)64
include $(BUILD_HOST_NATIVE_TEST)

include $(CLEAR_VARS)
LOCAL_MODULE := libcutils_test_static
LOCAL_SRC_FILES := $(test_src_files)
LOCAL_SRC_FILES_darwin := $(test_src_files_nonwindows)
LOCAL_SRC_FILES_linux := $(test_src_files_nonwindows)
LOCAL_STATIC_LIBRARIES := $(test_libraries)
LOCAL_LDLIBS_windows := -lws2_32
LOCAL_CXX_STL := libc++_static
LOCAL_MULTILIB := both
LOCAL_MODULE_STEM_32 := $(LOCAL_MODULE)32
LOCAL_MODULE_STEM_64 := $(LOCAL_MODULE)64
LOCAL_MODULE_HOST_OS := darwin linux windows
include $(BUILD_HOST_NATIVE_TEST)

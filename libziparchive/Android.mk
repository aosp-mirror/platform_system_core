#
# Copyright (C) 2013 The Android Open Source Project
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

source_files := zip_archive.cc
includes := external/zlib

include $(CLEAR_VARS)
LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
LOCAL_CPP_EXTENSION := .cc
LOCAL_SRC_FILES := ${source_files}
LOCAL_STATIC_LIBRARIES := libz
LOCAL_SHARED_LIBRARIES := libutils
LOCAL_MODULE:= libziparchive
LOCAL_C_INCLUDES += ${includes}
LOCAL_CFLAGS := -Werror
include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
LOCAL_MODULE := libziparchive
LOCAL_CPP_EXTENSION := .cc
LOCAL_SRC_FILES := ${source_files}
LOCAL_C_INCLUDES += ${includes}
LOCAL_STATIC_LIBRARIES := libz libutils
LOCAL_MODULE:= libziparchive-host
LOCAL_CFLAGS := -Werror
LOCAL_MULTILIB := both
include $(BUILD_HOST_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
LOCAL_MODULE := libziparchive
LOCAL_CPP_EXTENSION := .cc
LOCAL_SRC_FILES := ${source_files}
LOCAL_C_INCLUDES += ${includes}
LOCAL_STATIC_LIBRARIES := libz libutils
LOCAL_SHARED_LIBRARIES := liblog
LOCAL_MODULE:= libziparchive-host
LOCAL_CFLAGS := -Werror
LOCAL_MULTILIB := both
include $(BUILD_HOST_SHARED_LIBRARY)

# Tests.
include $(CLEAR_VARS)
LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
LOCAL_MODULE := ziparchive-tests
LOCAL_CPP_EXTENSION := .cc
LOCAL_CFLAGS := -Werror
LOCAL_SRC_FILES := zip_archive_test.cc
LOCAL_SHARED_LIBRARIES := liblog
LOCAL_STATIC_LIBRARIES := libziparchive libz libutils
include $(BUILD_NATIVE_TEST)

include $(CLEAR_VARS)
LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
LOCAL_MODULE := ziparchive-tests-host
LOCAL_CPP_EXTENSION := .cc
LOCAL_CFLAGS += \
    -Werror \
    -Wno-unnamed-type-template-args
LOCAL_SRC_FILES := zip_archive_test.cc
LOCAL_SHARED_LIBRARIES := libziparchive-host liblog
LOCAL_STATIC_LIBRARIES := \
    libz \
    libutils
include $(BUILD_HOST_NATIVE_TEST)

#
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
#

LOCAL_PATH := $(call my-dir)

binderwrapperCommonCFlags := -Wall -Werror -Wno-unused-parameter
binderwrapperCommonCFlags += -Wno-sign-promo  # for libchrome
binderwrapperCommonExportCIncludeDirs := $(LOCAL_PATH)/include
binderwrapperCommonCIncludes := $(LOCAL_PATH)/include
binderwrapperCommonSharedLibraries := \
  libbinder \
  libchrome \
  libutils \

# libbinderwrapper shared library
# ========================================================

include $(CLEAR_VARS)
LOCAL_MODULE := libbinderwrapper
LOCAL_CPP_EXTENSION := .cc
LOCAL_CFLAGS := $(binderwrapperCommonCFlags)
LOCAL_EXPORT_C_INCLUDE_DIRS := $(binderwrapperCommonExportCIncludeDirs)
LOCAL_C_INCLUDES := $(binderwrapperCommonCIncludes)
LOCAL_SHARED_LIBRARIES := $(binderwrapperCommonSharedLibraries)
LOCAL_SRC_FILES := \
  binder_wrapper.cc \
  real_binder_wrapper.cc \

include $(BUILD_SHARED_LIBRARY)

# libbinderwrapper_test_support static library
# ========================================================

include $(CLEAR_VARS)
LOCAL_MODULE := libbinderwrapper_test_support
LOCAL_CPP_EXTENSION := .cc
LOCAL_CFLAGS := $(binderwrapperCommonCFlags)
LOCAL_EXPORT_C_INCLUDE_DIRS := $(binderwrapperCommonExportCIncludeDirs)
LOCAL_C_INCLUDES := $(binderwrapperCommonCIncludes)
LOCAL_STATIC_LIBRARIES := libgtest
LOCAL_SHARED_LIBRARIES := \
  $(binderwrapperCommonSharedLibraries) \
  libbinderwrapper \

LOCAL_SRC_FILES := \
  binder_test_base.cc \
  stub_binder_wrapper.cc \

include $(BUILD_STATIC_LIBRARY)

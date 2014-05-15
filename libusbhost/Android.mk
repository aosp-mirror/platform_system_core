#
# Copyright (C) 2010 The Android Open Source Project
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

# Static library for Linux host
# ========================================================

ifeq ($(HOST_OS),linux)

include $(CLEAR_VARS)

LOCAL_MODULE := libusbhost
LOCAL_SRC_FILES := usbhost.c
LOCAL_CFLAGS := -Werror

include $(BUILD_HOST_STATIC_LIBRARY)

endif

# Shared library for target
# ========================================================

include $(CLEAR_VARS)

LOCAL_MODULE := libusbhost
LOCAL_SRC_FILES := usbhost.c

LOCAL_CFLAGS := -g -DUSE_LIBLOG -Werror

# needed for logcat
LOCAL_SHARED_LIBRARIES := libcutils

include $(BUILD_SHARED_LIBRARY)

# Static library for target
# ========================================================

include $(CLEAR_VARS)

LOCAL_MODULE := libusbhost
LOCAL_SRC_FILES := usbhost.c
LOCAL_CFLAGS := -Werror

include $(BUILD_STATIC_LIBRARY)

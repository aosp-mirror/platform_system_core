# Copyright (C) 2007 Google Inc.
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

LOCAL_PATH:= $(call my-dir)

fastboot_version := $(shell git -C $(LOCAL_PATH) rev-parse --short=12 HEAD 2>/dev/null)-android

include $(CLEAR_VARS)

LOCAL_C_INCLUDES := \
  $(LOCAL_PATH)/../adb \
  $(LOCAL_PATH)/../mkbootimg \
  $(LOCAL_PATH)/../../extras/ext4_utils \
  $(LOCAL_PATH)/../../extras/f2fs_utils \

LOCAL_SRC_FILES := protocol.cpp engine.cpp bootimg_utils.cpp fastboot.cpp util.cpp fs.cpp
LOCAL_MODULE := fastboot
LOCAL_MODULE_TAGS := debug
LOCAL_MODULE_HOST_OS := darwin linux windows
LOCAL_CONLYFLAGS += -std=gnu99
LOCAL_CFLAGS += -Wall -Wextra -Werror -Wunreachable-code

LOCAL_CFLAGS += -DFASTBOOT_REVISION='"$(fastboot_version)"'

LOCAL_SRC_FILES_linux := socket_unix.cpp usb_linux.cpp util_linux.cpp
LOCAL_STATIC_LIBRARIES_linux := libcutils libselinux

LOCAL_SRC_FILES_darwin := socket_unix.cpp usb_osx.cpp util_osx.cpp
LOCAL_STATIC_LIBRARIES_darwin := libcutils libselinux
LOCAL_LDLIBS_darwin := -lpthread -framework CoreFoundation -framework IOKit -framework Carbon
LOCAL_CFLAGS_darwin := -Wno-unused-parameter

LOCAL_SRC_FILES_windows := socket_windows.cpp usb_windows.cpp util_windows.cpp
LOCAL_STATIC_LIBRARIES_windows := AdbWinApi
LOCAL_REQUIRED_MODULES_windows := AdbWinApi
LOCAL_LDLIBS_windows := -lws2_32
LOCAL_C_INCLUDES_windows := development/host/windows/usb/api

LOCAL_STATIC_LIBRARIES := \
    libziparchive-host \
    libext4_utils_host \
    libsparse_host \
    libutils \
    liblog \
    libz \
    libdiagnose_usb \
    libbase \

# libf2fs_dlutils_host will dlopen("libf2fs_fmt_host_dyn")
LOCAL_CFLAGS_linux := -DUSE_F2FS
LOCAL_LDFLAGS_linux := -ldl -rdynamic -Wl,-rpath,.
LOCAL_REQUIRED_MODULES_linux := libf2fs_fmt_host_dyn
# The following libf2fs_* are from system/extras/f2fs_utils,
# and do not use code in external/f2fs-tools.
LOCAL_STATIC_LIBRARIES_linux += libf2fs_utils_host libf2fs_ioutils_host libf2fs_dlutils_host

LOCAL_CXX_STL := libc++_static

# Don't add anything here, we don't want additional shared dependencies
# on the host fastboot tool, and shared libraries that link against libc++
# will violate ODR
LOCAL_SHARED_LIBRARIES :=

include $(BUILD_HOST_EXECUTABLE)

my_dist_files := $(LOCAL_BUILT_MODULE)
ifeq ($(HOST_OS),linux)
my_dist_files += $(HOST_LIBRARY_PATH)/libf2fs_fmt_host_dyn$(HOST_SHLIB_SUFFIX)
endif
$(call dist-for-goals,dist_files sdk,$(my_dist_files))
my_dist_files :=

ifeq ($(HOST_OS),linux)
include $(CLEAR_VARS)
LOCAL_SRC_FILES := usbtest.cpp usb_linux.cpp util.cpp
LOCAL_MODULE := usbtest
LOCAL_CFLAGS := -Werror
LOCAL_STATIC_LIBRARIES := libbase
include $(BUILD_HOST_EXECUTABLE)
endif

# fastboot_test
# =========================================================
include $(CLEAR_VARS)

LOCAL_MODULE := fastboot_test
LOCAL_MODULE_HOST_OS := darwin linux windows

LOCAL_SRC_FILES := socket_test.cpp
LOCAL_STATIC_LIBRARIES := libbase

LOCAL_CFLAGS += -Wall -Wextra -Werror -Wunreachable-code

LOCAL_SRC_FILES_linux := socket_unix.cpp
LOCAL_STATIC_LIBRARIES_linux := libcutils

LOCAL_SRC_FILES_darwin := socket_unix.cpp
LOCAL_LDLIBS_darwin := -lpthread -framework CoreFoundation -framework IOKit -framework Carbon
LOCAL_CFLAGS_darwin := -Wno-unused-parameter
LOCAL_STATIC_LIBRARIES_darwin := libcutils

LOCAL_SRC_FILES_windows := socket_windows.cpp
LOCAL_LDLIBS_windows := -lws2_32

include $(BUILD_HOST_NATIVE_TEST)

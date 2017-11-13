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

include $(LOCAL_PATH)/../platform_tools_tool_version.mk

include $(CLEAR_VARS)

LOCAL_CFLAGS += -DFASTBOOT_VERSION="\"$(tool_version)\""

LOCAL_C_INCLUDES := \
  $(LOCAL_PATH)/../adb \
  $(LOCAL_PATH)/../mkbootimg \

LOCAL_SRC_FILES := \
    bootimg_utils.cpp \
    engine.cpp \
    fastboot.cpp \
    fs.cpp\
    protocol.cpp \
    socket.cpp \
    tcp.cpp \
    udp.cpp \
    util.cpp \

LOCAL_MODULE := fastboot
LOCAL_MODULE_TAGS := debug
LOCAL_MODULE_HOST_OS := darwin linux windows
LOCAL_CFLAGS += -Wall -Wextra -Werror -Wunreachable-code
LOCAL_REQUIRED_MODULES := mke2fs e2fsdroid

LOCAL_SRC_FILES_linux := usb_linux.cpp
LOCAL_STATIC_LIBRARIES_linux := libselinux

LOCAL_SRC_FILES_darwin := usb_osx.cpp
LOCAL_STATIC_LIBRARIES_darwin := libselinux
LOCAL_LDLIBS_darwin := -lpthread -framework CoreFoundation -framework IOKit -framework Carbon
LOCAL_CFLAGS_darwin := -Wno-unused-parameter

LOCAL_SRC_FILES_windows := usb_windows.cpp
LOCAL_STATIC_LIBRARIES_windows := AdbWinApi
LOCAL_REQUIRED_MODULES_windows := AdbWinApi AdbWinUsbApi
LOCAL_LDLIBS_windows := -lws2_32
LOCAL_C_INCLUDES_windows := development/host/windows/usb/api

LOCAL_STATIC_LIBRARIES := \
    libziparchive \
    libsparse \
    libutils \
    liblog \
    libz \
    libdiagnose_usb \
    libbase \
    libcutils \
    libgtest_host \

LOCAL_CFLAGS_linux := -DUSE_F2FS

LOCAL_CXX_STL := libc++_static

# Don't add anything here, we don't want additional shared dependencies
# on the host fastboot tool, and shared libraries that link against libc++
# will violate ODR
LOCAL_SHARED_LIBRARIES :=

include $(BUILD_HOST_EXECUTABLE)

my_dist_files := $(LOCAL_BUILT_MODULE)
my_dist_files += $(HOST_OUT_EXECUTABLES)/mke2fs$(HOST_EXECUTABLE_SUFFIX)
my_dist_files += $(HOST_OUT_EXECUTABLES)/e2fsdroid$(HOST_EXECUTABLE_SUFFIX)
$(call dist-for-goals,dist_files sdk win_sdk,$(my_dist_files))
ifdef HOST_CROSS_OS
# Archive fastboot.exe for win_sdk build.
$(call dist-for-goals,win_sdk,$(ALL_MODULES.host_cross_fastboot.BUILT))
endif
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

LOCAL_SRC_FILES := \
    socket.cpp \
    socket_mock.cpp \
    socket_test.cpp \
    tcp.cpp \
    tcp_test.cpp \
    udp.cpp \
    udp_test.cpp \

LOCAL_STATIC_LIBRARIES := libbase libcutils

LOCAL_CFLAGS += -Wall -Wextra -Werror -Wunreachable-code

LOCAL_LDLIBS_darwin := -lpthread -framework CoreFoundation -framework IOKit -framework Carbon
LOCAL_CFLAGS_darwin := -Wno-unused-parameter

LOCAL_LDLIBS_windows := -lws2_32

include $(BUILD_HOST_NATIVE_TEST)

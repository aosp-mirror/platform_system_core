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

fastboot_cflags := -Wall -Wextra -Werror -Wunreachable-code
fastboot_cflags += -DFASTBOOT_VERSION="\"$(tool_version)\""
fastboot_cflags_darwin := -Wno-unused-parameter
fastboot_ldlibs_darwin := -lpthread -framework CoreFoundation -framework IOKit -framework Carbon
fastboot_ldlibs_windows := -lws2_32
# Don't add anything here, we don't want additional shared dependencies
# on the host fastboot tool, and shared libraries that link against libc++
# will violate ODR.
fastboot_shared_libs :=
fastboot_static_libs := \
    libziparchive \
    libsparse \
    libutils \
    liblog \
    libz \
    libdiagnose_usb \
    libbase \
    libcutils \
    libgtest_host \

fastboot_stl := libc++_static

#
# Build host libfastboot.
#

include $(CLEAR_VARS)
LOCAL_MODULE := libfastboot
LOCAL_MODULE_HOST_OS := darwin linux windows

LOCAL_SRC_FILES := \
    bootimg_utils.cpp \
    engine.cpp \
    fastboot.cpp \
    fs.cpp \
    socket.cpp \
    tcp.cpp \
    udp.cpp \
    util.cpp \
    fastboot_driver.cpp \

LOCAL_SRC_FILES_darwin := usb_osx.cpp
LOCAL_SRC_FILES_linux := usb_linux.cpp
LOCAL_SRC_FILES_windows := usb_windows.cpp

LOCAL_C_INCLUDES_windows := development/host/windows/usb/api
LOCAL_CFLAGS := $(fastboot_cflags)
LOCAL_CFLAGS_darwin := $(fastboot_cflags_darwin)
LOCAL_CXX_STL := $(fastboot_stl)
LOCAL_HEADER_LIBRARIES := bootimg_headers
LOCAL_LDLIBS_darwin := $(fastboot_ldlibs_darwin)
LOCAL_LDLIBS_windows := $(fastboot_ldlibs_windows)
LOCAL_SHARED_LIBRARIES := $(fastboot_shared_libs)
LOCAL_STATIC_LIBRARIES := $(fastboot_static_libs)
include $(BUILD_HOST_STATIC_LIBRARY)

#
# Build host fastboot / fastboot.exe
#

include $(CLEAR_VARS)
LOCAL_MODULE := fastboot
LOCAL_MODULE_HOST_OS := darwin linux windows

LOCAL_CFLAGS := $(fastboot_cflags)
LOCAL_CFLAGS_darwin := $(fastboot_cflags_darwin)
LOCAL_CPP_STD := c++17
LOCAL_CXX_STL := $(fastboot_stl)
LOCAL_HEADER_LIBRARIES := bootimg_headers
LOCAL_LDLIBS_darwin := $(fastboot_ldlibs_darwin)
LOCAL_LDLIBS_windows := $(fastboot_ldlibs_windows)
LOCAL_REQUIRED_MODULES := mke2fs make_f2fs
LOCAL_REQUIRED_MODULES_darwin := e2fsdroid mke2fs.conf sload_f2fs
LOCAL_REQUIRED_MODULES_linux := e2fsdroid mke2fs.conf sload_f2fs
LOCAL_REQUIRED_MODULES_windows := AdbWinUsbApi
LOCAL_SRC_FILES := main.cpp
LOCAL_SHARED_LIBRARIES := $(fastboot_shared_libs)
LOCAL_SHARED_LIBRARIES_windows := AdbWinApi
LOCAL_STATIC_LIBRARIES := libfastboot $(fastboot_static_libs)
include $(BUILD_HOST_EXECUTABLE)

#
# Package fastboot-related executables.
#

my_dist_files := $(HOST_OUT_EXECUTABLES)/fastboot
my_dist_files += $(HOST_OUT_EXECUTABLES)/mke2fs
my_dist_files += $(HOST_OUT_EXECUTABLES)/e2fsdroid
my_dist_files += $(HOST_OUT_EXECUTABLES)/make_f2fs
my_dist_files += $(HOST_OUT_EXECUTABLES)/sload_f2fs
$(call dist-for-goals,dist_files sdk win_sdk,$(my_dist_files))
ifdef HOST_CROSS_OS
$(call dist-for-goals,dist_files sdk win_sdk,$(ALL_MODULES.host_cross_fastboot.BUILT))
endif
my_dist_files :=

#
# Build host fastboot_test.
#

include $(CLEAR_VARS)
LOCAL_MODULE := fastboot_test
LOCAL_MODULE_HOST_OS := darwin linux windows
LOCAL_MODULE_HOST_CROSS_ARCH := x86 # Avoid trying to build for win64.

LOCAL_SRC_FILES := \
    fastboot_test.cpp \
    socket_mock.cpp \
    socket_test.cpp \
    tcp_test.cpp \
    udp_test.cpp \

LOCAL_CFLAGS := $(fastboot_cflags)
LOCAL_CFLAGS_darwin := $(fastboot_cflags_darwin)
LOCAL_CXX_STL := $(fastboot_stl)
LOCAL_HEADER_LIBRARIES := bootimg_headers
LOCAL_LDLIBS_darwin := $(fastboot_ldlibs_darwin)
LOCAL_LDLIBS_windows := $(fastboot_ldlibs_windows)
LOCAL_SHARED_LIBRARIES := $(fastboot_shared_libs)
LOCAL_SHARED_LIBRARIES_windows := AdbWinApi
LOCAL_STATIC_LIBRARIES := libfastboot $(fastboot_static_libs)
include $(BUILD_HOST_NATIVE_TEST)

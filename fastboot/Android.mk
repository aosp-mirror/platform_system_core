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

include $(CLEAR_VARS)

LOCAL_C_INCLUDES := $(LOCAL_PATH)/../mkbootimg \
  $(LOCAL_PATH)/../../extras/ext4_utils \
  $(LOCAL_PATH)/../../extras/f2fs_utils
LOCAL_SRC_FILES := protocol.c engine.c bootimg.c fastboot.c util.c fs.c
LOCAL_MODULE := fastboot
LOCAL_MODULE_TAGS := debug
LOCAL_CFLAGS += -std=gnu99 -Werror

ifeq ($(HOST_OS),linux)
  LOCAL_SRC_FILES += usb_linux.c util_linux.c
endif

ifeq ($(HOST_OS),darwin)
  LOCAL_SRC_FILES += usb_osx.c util_osx.c
  LOCAL_LDLIBS += -lpthread -framework CoreFoundation -framework IOKit \
	-framework Carbon
endif

ifeq ($(HOST_OS),windows)
  LOCAL_SRC_FILES += usb_windows.c util_windows.c
  EXTRA_STATIC_LIBS := AdbWinApi
  ifneq ($(strip $(USE_CYGWIN)),)
    # Pure cygwin case
    LOCAL_LDLIBS += -lpthread
  endif
  ifneq ($(strip $(USE_MINGW)),)
    # MinGW under Linux case
    LOCAL_LDLIBS += -lws2_32
    USE_SYSDEPS_WIN32 := 1
  endif
  LOCAL_C_INCLUDES += development/host/windows/usb/api
endif

LOCAL_STATIC_LIBRARIES := \
    $(EXTRA_STATIC_LIBS) \
    libzipfile \
    libunz \
    libext4_utils_host \
    libsparse_host \
    libz

ifneq ($(HOST_OS),windows)
LOCAL_STATIC_LIBRARIES += libselinux
endif # HOST_OS != windows

ifeq ($(HOST_OS),linux)
# libf2fs_dlutils_host will dlopen("libf2fs_fmt_host_dyn")
LOCAL_CFLAGS += -DUSE_F2FS
LOCAL_LDFLAGS += -ldl -rdynamic -Wl,-rpath,.
LOCAL_REQUIRED_MODULES := libf2fs_fmt_host_dyn
# The following libf2fs_* are from system/extras/f2fs_utils,
# and do not use code in external/f2fs-tools.
LOCAL_STATIC_LIBRARIES += libf2fs_utils_host libf2fs_ioutils_host libf2fs_dlutils_host
endif

include $(BUILD_HOST_EXECUTABLE)

my_dist_files := $(LOCAL_BUILT_MODULE)
ifeq ($(HOST_OS),linux)
my_dist_files += $(HOST_LIBRARY_PATH)/libf2fs_fmt_host_dyn$(HOST_SHLIB_SUFFIX)
endif
$(call dist-for-goals,dist_files sdk,$(my_dist_files))
my_dist_files :=


ifeq ($(HOST_OS),linux)
include $(CLEAR_VARS)
LOCAL_SRC_FILES := usbtest.c usb_linux.c util.c
LOCAL_MODULE := usbtest
LOCAL_CFLAGS := -Werror
include $(BUILD_HOST_EXECUTABLE)
endif

ifeq ($(HOST_OS),windows)
$(LOCAL_INSTALLED_MODULE): $(HOST_OUT_EXECUTABLES)/AdbWinApi.dll
endif

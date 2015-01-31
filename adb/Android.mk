# Copyright 2005 The Android Open Source Project
#
# Android.mk for adb
#

LOCAL_PATH:= $(call my-dir)

# libadb
# =========================================================

# Much of adb is duplicated in bootable/recovery/minadb and fastboot. Changes
# made to adb rarely get ported to the other two, so the trees have diverged a
# bit. We'd like to stop this because it is a maintenance nightmare, but the
# divergence makes this difficult to do all at once. For now, we will start
# small by moving common files into a static library. Hopefully some day we can
# get enough of adb in here that we no longer need minadb. https://b/17626262
LIBADB_SRC_FILES :=
LIBADB_C_FLAGS := -Wall -Werror -D_XOPEN_SOURCE -D_GNU_SOURCE

include $(CLEAR_VARS)
LOCAL_MODULE := libadb
LOCAL_CFLAGS := $(LIBADB_CFLAGS) -DADB_HOST=0
LOCAL_SRC_FILES := $(LIBADB_SRC_FILES) fdevent.cpp
include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := libadb
LOCAL_CFLAGS := $(LIBADB_CFLAGS) -DADB_HOST=1
LOCAL_SRC_FILES := $(LIBADB_SRC_FILES)
ifeq ($(HOST_OS),windows)
    LOCAL_SRC_FILES += sysdeps_win32.c
else
    LOCAL_SRC_FILES += fdevent.cpp
endif
include $(BUILD_HOST_STATIC_LIBRARY)

# adb host tool
# =========================================================
include $(CLEAR_VARS)

# Default to a virtual (sockets) usb interface
USB_SRCS :=
EXTRA_SRCS :=

ifeq ($(HOST_OS),linux)
  USB_SRCS := usb_linux.c
  EXTRA_SRCS := get_my_path_linux.c
  LOCAL_LDLIBS += -lrt -ldl -lpthread
  LOCAL_CFLAGS += -DWORKAROUND_BUG6558362
endif

ifeq ($(HOST_OS),darwin)
  USB_SRCS := usb_osx.c
  EXTRA_SRCS := get_my_path_darwin.c
  LOCAL_LDLIBS += -lpthread -framework CoreFoundation -framework IOKit -framework Carbon
  LOCAL_CFLAGS += -Wno-sizeof-pointer-memaccess -Wno-unused-parameter
endif

ifeq ($(HOST_OS),windows)
  USB_SRCS := usb_windows.c
  EXTRA_SRCS := get_my_path_windows.c
  EXTRA_STATIC_LIBS := AdbWinApi
  ifneq ($(strip $(USE_MINGW)),)
    # MinGW under Linux case
    LOCAL_LDLIBS += -lws2_32 -lgdi32
    USE_SYSDEPS_WIN32 := 1
  endif
  LOCAL_C_INCLUDES += development/host/windows/usb/api/
endif

LOCAL_SRC_FILES := \
	adb.c \
	console.c \
	transport.c \
	transport_local.c \
	transport_usb.c \
	commandline.c \
	adb_client.c \
	adb_auth_host.c \
	sockets.c \
	services.c \
	file_sync_client.c \
	$(EXTRA_SRCS) \
	$(USB_SRCS) \

ifneq ($(USE_SYSDEPS_WIN32),)
  LOCAL_SRC_FILES += sysdeps_win32.c
endif

LOCAL_CFLAGS += -O2 -g -DADB_HOST=1 -Wall -Wno-unused-parameter -Werror
LOCAL_CFLAGS += -D_XOPEN_SOURCE -D_GNU_SOURCE
LOCAL_MODULE := adb
LOCAL_MODULE_TAGS := debug

LOCAL_STATIC_LIBRARIES := \
    libadb \
    libzipfile \
    libcrypto_static \
    $(EXTRA_STATIC_LIBS) \

ifeq ($(USE_SYSDEPS_WIN32),)
	LOCAL_STATIC_LIBRARIES += libcutils
endif

LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
include $(BUILD_HOST_EXECUTABLE)

$(call dist-for-goals,dist_files sdk,$(LOCAL_BUILT_MODULE))

ifeq ($(HOST_OS),windows)
$(LOCAL_INSTALLED_MODULE): \
    $(HOST_OUT_EXECUTABLES)/AdbWinApi.dll \
    $(HOST_OUT_EXECUTABLES)/AdbWinUsbApi.dll
endif


# adbd device daemon
# =========================================================

include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
	adb.c \
	transport.c \
	transport_local.c \
	transport_usb.c \
	adb_auth_client.c \
	sockets.c \
	services.c \
	file_sync_service.c \
	jdwp_service.c \
	framebuffer_service.c \
	remount_service.c \
	set_verity_enable_state_service.c \
	usb_linux_client.c

LOCAL_CFLAGS := \
	-O2 \
	-g \
	-DADB_HOST=0 \
	-D_XOPEN_SOURCE \
	-D_GNU_SOURCE \
	-Wall -Wno-unused-parameter -Werror -Wno-deprecated-declarations \

ifneq (,$(filter userdebug eng,$(TARGET_BUILD_VARIANT)))
LOCAL_CFLAGS += -DALLOW_ADBD_ROOT=1
endif

ifneq (,$(filter userdebug,$(TARGET_BUILD_VARIANT)))
LOCAL_CFLAGS += -DALLOW_ADBD_DISABLE_VERITY=1
endif

LOCAL_MODULE := adbd

LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_MODULE_PATH := $(TARGET_ROOT_OUT_SBIN)
LOCAL_UNSTRIPPED_PATH := $(TARGET_ROOT_OUT_SBIN_UNSTRIPPED)
LOCAL_C_INCLUDES += system/extras/ext4_utils system/core/fs_mgr/include

LOCAL_STATIC_LIBRARIES := \
    libadb \
    libfs_mgr \
    liblog \
    libcutils \
    libc \
    libmincrypt \
    libselinux \
    libext4_utils_static \

LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk

include $(BUILD_EXECUTABLE)

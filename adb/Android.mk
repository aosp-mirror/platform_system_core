# Copyright 2005 The Android Open Source Project
#
# Android.mk for adb
#

LOCAL_PATH:= $(call my-dir)

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
endif

ifeq ($(HOST_OS),freebsd)
  USB_SRCS := usb_libusb.c
  EXTRA_SRCS := get_my_path_freebsd.c
  LOCAL_LDLIBS += -lpthread -lusb
endif

ifeq ($(HOST_OS),windows)
  USB_SRCS := usb_windows.c
  EXTRA_SRCS := get_my_path_windows.c
  EXTRA_STATIC_LIBS := AdbWinApi
  ifneq ($(strip $(USE_CYGWIN)),)
    # Pure cygwin case
    LOCAL_LDLIBS += -lpthread -lgdi32
  endif
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
	usb_vendors.c

LOCAL_C_INCLUDES += external/openssl/include

ifneq ($(USE_SYSDEPS_WIN32),)
  LOCAL_SRC_FILES += sysdeps_win32.c
else
  LOCAL_SRC_FILES += fdevent.c
endif

LOCAL_CFLAGS += -O2 -g -DADB_HOST=1 -Wall -Wno-unused-parameter -Werror
LOCAL_CFLAGS += -D_XOPEN_SOURCE -D_GNU_SOURCE
LOCAL_MODULE := adb
LOCAL_MODULE_TAGS := debug

LOCAL_STATIC_LIBRARIES := libzipfile libunz libcrypto_static $(EXTRA_STATIC_LIBS)
ifeq ($(USE_SYSDEPS_WIN32),)
	LOCAL_STATIC_LIBRARIES += libcutils
endif

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
	fdevent.c \
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
	disable_verity_service.c \
	usb_linux_client.c

LOCAL_CFLAGS := -O2 -g -DADB_HOST=0 -Wall -Wno-unused-parameter -Werror
LOCAL_CFLAGS += -D_XOPEN_SOURCE -D_GNU_SOURCE

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

LOCAL_STATIC_LIBRARIES := liblog \
	libfs_mgr \
	libcutils \
	libc \
	libmincrypt \
	libselinux \
	libext4_utils_static

include $(BUILD_EXECUTABLE)


# adb host tool for device-as-host
# =========================================================
ifneq ($(SDK_ONLY),true)
include $(CLEAR_VARS)

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
	get_my_path_linux.c \
	usb_linux.c \
	usb_vendors.c \
	fdevent.c

LOCAL_CFLAGS := \
	-O2 \
	-g \
	-DADB_HOST=1 \
	-DADB_HOST_ON_TARGET=1 \
	-Wall -Wno-unused-parameter -Werror \
	-D_XOPEN_SOURCE \
	-D_GNU_SOURCE

LOCAL_C_INCLUDES += external/openssl/include

LOCAL_MODULE := adb

LOCAL_STATIC_LIBRARIES := libzipfile libunz libcutils liblog

LOCAL_SHARED_LIBRARIES := libcrypto

include $(BUILD_EXECUTABLE)
endif

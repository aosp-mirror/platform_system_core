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
  LOCAL_LDLIBS += -lrt -lncurses -lpthread
endif

ifeq ($(HOST_OS),darwin)
  USB_SRCS := usb_osx.c
  EXTRA_SRCS := get_my_path_darwin.c
  LOCAL_LDLIBS += -lpthread -framework CoreFoundation -framework IOKit -framework Carbon
endif

ifeq ($(HOST_OS),windows)
  USB_SRCS := usb_windows.c
  EXTRA_SRCS := get_my_path_windows.c
  EXTRA_STATIC_LIBS := AdbWinApi
  LOCAL_C_INCLUDES += /usr/include/w32api/ddk $(LOCAL_PATH)/../windows/usb/api
  ifneq ($(strip $(USE_CYGWIN)),)
    LOCAL_LDLIBS += -lpthread
  else
    LOCAL_LDLIBS += -lws2_32
    USE_SYSDEPS_WIN32 := 1
  endif
endif

LOCAL_SRC_FILES := \
	adb.c \
	console.c \
	transport.c \
	transport_local.c \
	transport_usb.c \
	commandline.c \
	adb_client.c \
	sockets.c \
	services.c \
	file_sync_client.c \
	$(EXTRA_SRCS) \
	$(USB_SRCS) \
	shlist.c


ifneq ($(USE_SYSDEPS_WIN32),)
  LOCAL_SRC_FILES += sysdeps_win32.c
endif

LOCAL_CFLAGS += -O2 -g -DADB_HOST=1  -Wall -Wno-unused-parameter
LOCAL_CFLAGS += -D_XOPEN_SOURCE -D_GNU_SOURCE -DSH_HISTORY
LOCAL_MODULE := adb

LOCAL_STATIC_LIBRARIES := libzipfile libunz $(EXTRA_STATIC_LIBS)
ifeq ($(USE_SYSDEPS_WIN32),)
	LOCAL_STATIC_LIBRARIES += libcutils
endif

include $(BUILD_HOST_EXECUTABLE)

ifeq ($(HOST_OS),windows)
$(LOCAL_INSTALLED_MODULE): $(HOST_OUT_EXECUTABLES)/AdbWinApi.dll
endif

ifeq ($(HOST_OS),linux)
include $(CLEAR_VARS)
LOCAL_SRC_FILES := \
	kdbg.c
LOCAL_MODULE := kdbg
include $(BUILD_HOST_EXECUTABLE)
endif


# adbd device daemon
# =========================================================
ifeq ($(TARGET_ARCH),arm)
include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
	adb.c \
	transport.c \
	transport_local.c \
	transport_usb.c \
	sockets.c \
	services.c \
	file_sync_service.c \
	jdwp_service.c \
	framebuffer_service.c \
	remount_service.c \
	usb_linux_client.c \
	log_service.c


LOCAL_CFLAGS := -O2 -g -DADB_HOST=0 -DANDROID_GADGET=1 -Wall -Wno-unused-parameter
LOCAL_CFLAGS += -D_XOPEN_SOURCE -D_GNU_SOURCE
LOCAL_MODULE := adbd

LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_MODULE_PATH := $(TARGET_ROOT_OUT_SBIN)
LOCAL_UNSTRIPPED_PATH := $(TARGET_ROOT_OUT_SBIN_UNSTRIPPED)

LOCAL_STATIC_LIBRARIES := libcutils libc

include $(BUILD_EXECUTABLE)
endif

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
    LOCAL_LDLIBS += -lpthread
    LOCAL_C_INCLUDES += /usr/include/w32api/ddk
  endif
  ifneq ($(strip $(USE_MINGW)),)
    # MinGW under Linux case
    LOCAL_LDLIBS += -lws2_32
    USE_SYSDEPS_WIN32 := 1
    LOCAL_C_INCLUDES += /usr/i586-mingw32msvc/include/ddk
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
	sockets.c \
	services.c \
	file_sync_client.c \
	$(EXTRA_SRCS) \
	$(USB_SRCS) \
	shlist.c \
	utils.c \
	usb_vendors.c


ifneq ($(USE_SYSDEPS_WIN32),)
  LOCAL_SRC_FILES += sysdeps_win32.c
else
  LOCAL_SRC_FILES += fdevent.c
endif

LOCAL_CFLAGS += -O2 -g -DADB_HOST=1  -Wall -Wno-unused-parameter
LOCAL_CFLAGS += -D_XOPEN_SOURCE -D_GNU_SOURCE -DSH_HISTORY
LOCAL_MODULE := adb

LOCAL_STATIC_LIBRARIES := libzipfile libunz $(EXTRA_STATIC_LIBS)
ifeq ($(USE_SYSDEPS_WIN32),)
	LOCAL_STATIC_LIBRARIES += libcutils
endif
ifeq ($(HOST_OS),linux)
  LOCAL_STATIC_LIBRARIES += libusbhost
endif

include $(BUILD_HOST_EXECUTABLE)

$(call dist-for-goals,droid,$(LOCAL_BUILT_MODULE))

ifeq ($(HOST_OS),windows)
$(LOCAL_INSTALLED_MODULE): \
    $(HOST_OUT_EXECUTABLES)/AdbWinApi.dll \
    $(HOST_OUT_EXECUTABLES)/AdbWinUsbApi.dll
endif


# adbd device daemon
# =========================================================

# build adbd in all non-simulator builds
BUILD_ADBD := false
ifneq ($(TARGET_SIMULATOR),true)
    BUILD_ADBD := true
endif

# build adbd for the Linux simulator build
# so we can use it to test the adb USB gadget driver on x86
#ifeq ($(HOST_OS),linux)
#    BUILD_ADBD := true
#endif


ifeq ($(BUILD_ADBD),true)
include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
	adb.c \
	fdevent.c \
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
	log_service.c \
	utils.c

LOCAL_CFLAGS := -O2 -g -DADB_HOST=0 -Wall -Wno-unused-parameter
LOCAL_CFLAGS += -D_XOPEN_SOURCE -D_GNU_SOURCE

# TODO: This should probably be board specific, whether or not the kernel has
# the gadget driver; rather than relying on the architecture type.
ifeq ($(TARGET_ARCH),arm)
LOCAL_CFLAGS += -DANDROID_GADGET=1
endif

LOCAL_MODULE := adbd

LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_MODULE_PATH := $(TARGET_ROOT_OUT_SBIN)
LOCAL_UNSTRIPPED_PATH := $(TARGET_ROOT_OUT_SBIN_UNSTRIPPED)

ifeq ($(TARGET_SIMULATOR),true)
  LOCAL_STATIC_LIBRARIES := libcutils
  LOCAL_LDLIBS += -lpthread
  include $(BUILD_HOST_EXECUTABLE)
else
  LOCAL_STATIC_LIBRARIES := libcutils libc
  include $(BUILD_EXECUTABLE)
endif

endif

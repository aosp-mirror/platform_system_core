# Copyright 2005 The Android Open Source Project
#
# Android.mk for adb
#

LOCAL_PATH:= $(call my-dir)

ADB_CLANG :=

# libadb
# =========================================================

# Much of adb is duplicated in bootable/recovery/minadb and fastboot. Changes
# made to adb rarely get ported to the other two, so the trees have diverged a
# bit. We'd like to stop this because it is a maintenance nightmare, but the
# divergence makes this difficult to do all at once. For now, we will start
# small by moving common files into a static library. Hopefully some day we can
# get enough of adb in here that we no longer need minadb. https://b/17626262
LIBADB_SRC_FILES := \
    adb.cpp \
    adb_auth.cpp \
    adb_io.cpp \
    adb_listeners.cpp \
    sockets.cpp \
    transport.cpp \
    transport_local.cpp \
    transport_usb.cpp \

LIBADB_CFLAGS := \
    -Wall -Werror \
    -Wno-unused-parameter \
    -Wno-missing-field-initializers \
    -fvisibility=hidden \

LIBADB_darwin_SRC_FILES := \
    fdevent.cpp \
    get_my_path_darwin.cpp \
    usb_osx.c \

LIBADB_linux_SRC_FILES := \
    fdevent.cpp \
    get_my_path_linux.cpp \
    usb_linux.cpp \

LIBADB_windows_SRC_FILES := \
    get_my_path_windows.cpp \
    sysdeps_win32.cpp \
    usb_windows.cpp \

include $(CLEAR_VARS)
LOCAL_CLANG := true
LOCAL_MODULE := libadbd
LOCAL_CFLAGS := $(LIBADB_CFLAGS) -DADB_HOST=0
LOCAL_SRC_FILES := \
    $(LIBADB_SRC_FILES) \
    adb_auth_client.cpp \
    fdevent.cpp \
    jdwp_service.cpp \
    qemu_tracing.cpp \
    usb_linux_client.cpp \

include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_CLANG := $(ADB_CLANG)
LOCAL_MODULE := libadb
LOCAL_CFLAGS := $(LIBADB_CFLAGS) -DADB_HOST=1
LOCAL_SRC_FILES := \
    $(LIBADB_SRC_FILES) \
    $(LIBADB_$(HOST_OS)_SRC_FILES) \
    adb_auth_host.cpp \

# Even though we're building a static library (and thus there's no link step for
# this to take effect), this adds the SSL includes to our path.
LOCAL_STATIC_LIBRARIES := libcrypto_static

ifeq ($(HOST_OS),windows)
    LOCAL_C_INCLUDES += development/host/windows/usb/api/
endif

include $(BUILD_HOST_STATIC_LIBRARY)

LIBADB_TEST_SRCS := \
    adb_io_test.cpp \
    transport_test.cpp \

include $(CLEAR_VARS)
LOCAL_CLANG := $(ADB_CLANG)
LOCAL_MODULE := adbd_test
LOCAL_CFLAGS := -DADB_HOST=0 $(LIBADB_CFLAGS)
LOCAL_SRC_FILES := $(LIBADB_TEST_SRCS)
LOCAL_STATIC_LIBRARIES := libadbd
LOCAL_SHARED_LIBRARIES := liblog libbase libcutils
include $(BUILD_NATIVE_TEST)

include $(CLEAR_VARS)
LOCAL_CLANG := $(ADB_CLANG)
LOCAL_MODULE := adb_test
LOCAL_CFLAGS := -DADB_HOST=1 $(LIBADB_CFLAGS)
LOCAL_SRC_FILES := $(LIBADB_TEST_SRCS) services.cpp
LOCAL_SHARED_LIBRARIES := liblog libbase
LOCAL_STATIC_LIBRARIES := \
    libadb \
    libcrypto_static \
    libcutils \

ifeq ($(HOST_OS),linux)
  LOCAL_LDLIBS += -lrt -ldl -lpthread
endif

include $(BUILD_HOST_NATIVE_TEST)

# adb host tool
# =========================================================
include $(CLEAR_VARS)

ifeq ($(HOST_OS),linux)
  LOCAL_LDLIBS += -lrt -ldl -lpthread
  LOCAL_CFLAGS += -DWORKAROUND_BUG6558362
endif

ifeq ($(HOST_OS),darwin)
  LOCAL_LDLIBS += -lpthread -framework CoreFoundation -framework IOKit -framework Carbon
  LOCAL_CFLAGS += -Wno-sizeof-pointer-memaccess -Wno-unused-parameter
endif

ifeq ($(HOST_OS),windows)
  EXTRA_STATIC_LIBS := AdbWinApi
  ifneq ($(strip $(USE_MINGW)),)
    # MinGW under Linux case
    LOCAL_LDLIBS += -lws2_32 -lgdi32
    USE_SYSDEPS_WIN32 := 1
  endif
endif

LOCAL_CLANG := $(ADB_CLANG)

LOCAL_SRC_FILES := \
    adb_main.cpp \
    console.cpp \
    commandline.cpp \
    adb_client.cpp \
    services.cpp \
    file_sync_client.cpp \

LOCAL_CFLAGS += \
    -Wall -Werror \
    -Wno-unused-parameter \
    -D_GNU_SOURCE \
    -DADB_HOST=1 \

LOCAL_MODULE := adb
LOCAL_MODULE_TAGS := debug

LOCAL_STATIC_LIBRARIES := \
    libadb \
    libcrypto_static \
    $(EXTRA_STATIC_LIBS) \

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

LOCAL_CLANG := $(ADB_CLANG)

LOCAL_SRC_FILES := \
    adb_main.cpp \
    services.cpp \
    file_sync_service.cpp \
    framebuffer_service.cpp \
    remount_service.cpp \
    set_verity_enable_state_service.cpp \

LOCAL_CFLAGS := \
    -DADB_HOST=0 \
    -D_GNU_SOURCE \
    -Wall -Werror \
    -Wno-unused-parameter \
    -Wno-deprecated-declarations \

ifneq (,$(filter userdebug eng,$(TARGET_BUILD_VARIANT)))
LOCAL_CFLAGS += -DALLOW_ADBD_ROOT=1
endif

ifneq (,$(filter userdebug eng,$(TARGET_BUILD_VARIANT)))
LOCAL_CFLAGS += -DALLOW_ADBD_DISABLE_VERITY=1
endif

LOCAL_MODULE := adbd

LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_MODULE_PATH := $(TARGET_ROOT_OUT_SBIN)
LOCAL_UNSTRIPPED_PATH := $(TARGET_ROOT_OUT_SBIN_UNSTRIPPED)
LOCAL_C_INCLUDES += system/extras/ext4_utils

LOCAL_STATIC_LIBRARIES := \
    libadbd \
    libbase \
    libfs_mgr \
    liblog \
    libcutils \
    libc \
    libmincrypt \
    libselinux \
    libext4_utils_static \

include $(BUILD_EXECUTABLE)

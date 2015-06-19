# Copyright 2005 The Android Open Source Project
#
# Android.mk for adb
#

LOCAL_PATH:= $(call my-dir)

ifeq ($(HOST_OS),windows)
    adb_host_clang := false  # libc++ for mingw not ready yet.
else
    adb_host_clang := true
endif

adb_version := $(shell git -C $(LOCAL_PATH) rev-parse --short=12 HEAD 2>/dev/null)-android

ADB_COMMON_CFLAGS := \
    -Wall -Wextra -Werror \
    -Wno-unused-parameter \
    -Wno-missing-field-initializers \
    -DADB_REVISION='"$(adb_version)"' \

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
    adb_utils.cpp \
    sockets.cpp \
    transport.cpp \
    transport_local.cpp \
    transport_usb.cpp \

LIBADB_TEST_SRCS := \
    adb_io_test.cpp \
    adb_utils_test.cpp \
    transport_test.cpp \

LIBADB_CFLAGS := \
    $(ADB_COMMON_CFLAGS) \
    -fvisibility=hidden \

LIBADB_darwin_SRC_FILES := \
    fdevent.cpp \
    get_my_path_darwin.cpp \
    usb_osx.cpp \

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

LOCAL_SHARED_LIBRARIES := libbase

# Even though we're building a static library (and thus there's no link step for
# this to take effect), this adds the includes to our path.
LOCAL_STATIC_LIBRARIES := libbase

include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_CLANG := $(adb_host_clang)
LOCAL_MODULE := libadb
LOCAL_CFLAGS := $(LIBADB_CFLAGS) -DADB_HOST=1
LOCAL_SRC_FILES := \
    $(LIBADB_SRC_FILES) \
    $(LIBADB_$(HOST_OS)_SRC_FILES) \
    adb_auth_host.cpp \

LOCAL_SHARED_LIBRARIES := libbase

# Even though we're building a static library (and thus there's no link step for
# this to take effect), this adds the includes to our path.
LOCAL_STATIC_LIBRARIES := libcrypto_static libbase

ifeq ($(HOST_OS),windows)
    LOCAL_C_INCLUDES += development/host/windows/usb/api/
endif

include $(BUILD_HOST_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_CLANG := true
LOCAL_MODULE := adbd_test
LOCAL_CFLAGS := -DADB_HOST=0 $(LIBADB_CFLAGS)
LOCAL_SRC_FILES := $(LIBADB_TEST_SRCS)
LOCAL_STATIC_LIBRARIES := libadbd
LOCAL_SHARED_LIBRARIES := liblog libbase libcutils
include $(BUILD_NATIVE_TEST)

ifneq ($(HOST_OS),windows)
include $(CLEAR_VARS)
LOCAL_CLANG := $(adb_host_clang)
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

ifeq ($(HOST_OS),darwin)
    LOCAL_LDLIBS += -framework CoreFoundation -framework IOKit
endif

include $(BUILD_HOST_NATIVE_TEST)
endif

# adb device tracker (used by ddms) test tool
# =========================================================

ifeq ($(HOST_OS),linux)
include $(CLEAR_VARS)
LOCAL_CLANG := $(adb_host_clang)
LOCAL_MODULE := adb_device_tracker_test
LOCAL_CFLAGS := -DADB_HOST=1 $(LIBADB_CFLAGS)
LOCAL_SRC_FILES := test_track_devices.cpp
LOCAL_SHARED_LIBRARIES := liblog libbase
LOCAL_STATIC_LIBRARIES := libadb libcrypto_static libcutils
LOCAL_LDLIBS += -lrt -ldl -lpthread
include $(BUILD_HOST_EXECUTABLE)
endif

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
    LOCAL_LDLIBS += -lws2_32 -lgdi32
    EXTRA_STATIC_LIBS := AdbWinApi
endif

LOCAL_CLANG := $(adb_host_clang)

LOCAL_SRC_FILES := \
    client/main.cpp \
    console.cpp \
    commandline.cpp \
    adb_client.cpp \
    services.cpp \
    file_sync_client.cpp \

LOCAL_CFLAGS += \
    $(ADB_COMMON_CFLAGS) \
    -D_GNU_SOURCE \
    -DADB_HOST=1 \

LOCAL_MODULE := adb
LOCAL_MODULE_TAGS := debug

LOCAL_STATIC_LIBRARIES := \
    libadb \
    libbase \
    libcrypto_static \
    libcutils \
    liblog \
    $(EXTRA_STATIC_LIBS) \

# libc++ not available on windows yet
ifneq ($(HOST_OS),windows)
    LOCAL_CXX_STL := libc++_static
endif

# Don't add anything here, we don't want additional shared dependencies
# on the host adb tool, and shared libraries that link against libc++
# will violate ODR
LOCAL_SHARED_LIBRARIES :=

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

LOCAL_CLANG := true

LOCAL_SRC_FILES := \
    daemon/main.cpp \
    services.cpp \
    file_sync_service.cpp \
    framebuffer_service.cpp \
    remount_service.cpp \
    set_verity_enable_state_service.cpp \

LOCAL_CFLAGS := \
    $(ADB_COMMON_CFLAGS) \
    -DADB_HOST=0 \
    -D_GNU_SOURCE \
    -Wno-deprecated-declarations \

LOCAL_CFLAGS += -DALLOW_ADBD_NO_AUTH=$(if $(filter userdebug eng,$(TARGET_BUILD_VARIANT)),1,0)

ifneq (,$(filter userdebug eng,$(TARGET_BUILD_VARIANT)))
LOCAL_CFLAGS += -DALLOW_ADBD_DISABLE_VERITY=1
LOCAL_CFLAGS += -DALLOW_ADBD_ROOT=1
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
    libmincrypt \
    libselinux \
    libext4_utils_static \
    libcutils \
    libbase \

include $(BUILD_EXECUTABLE)

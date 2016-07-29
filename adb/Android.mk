# Copyright 2005 The Android Open Source Project
#
# Android.mk for adb
#

LOCAL_PATH:= $(call my-dir)

adb_host_sanitize :=
adb_target_sanitize :=

adb_version := $(shell git -C $(LOCAL_PATH) rev-parse --short=12 HEAD 2>/dev/null)-android

ADB_COMMON_CFLAGS := \
    -Wall -Wextra -Werror \
    -Wno-unused-parameter \
    -Wno-missing-field-initializers \
    -Wvla \
    -DADB_REVISION='"$(adb_version)"' \

ADB_COMMON_linux_CFLAGS := \
    -std=c++14 \
    -Wexit-time-destructors \

ADB_COMMON_darwin_CFLAGS := \
    -std=c++14 \
    -Wexit-time-destructors \

# Define windows.h and tchar.h Unicode preprocessor symbols so that
# CreateFile(), _tfopen(), etc. map to versions that take wchar_t*, breaking the
# build if you accidentally pass char*. Fix by calling like:
#   std::wstring path_wide;
#   if (!android::base::UTF8ToWide(path_utf8, &path_wide)) { /* error handling */ }
#   CreateFileW(path_wide.c_str());
ADB_COMMON_windows_CFLAGS := \
    -DUNICODE=1 -D_UNICODE=1 \

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
    adb_trace.cpp \
    adb_utils.cpp \
    fdevent.cpp \
    sockets.cpp \
    transport.cpp \
    transport_local.cpp \
    transport_usb.cpp \

LIBADB_TEST_SRCS := \
    adb_io_test.cpp \
    adb_utils_test.cpp \
    fdevent_test.cpp \
    socket_test.cpp \
    sysdeps_test.cpp \
    sysdeps/stat_test.cpp \
    transport_test.cpp \

LIBADB_CFLAGS := \
    $(ADB_COMMON_CFLAGS) \
    -fvisibility=hidden \

LIBADB_linux_CFLAGS := \
    $(ADB_COMMON_linux_CFLAGS) \

LIBADB_darwin_CFLAGS := \
    $(ADB_COMMON_darwin_CFLAGS) \

LIBADB_windows_CFLAGS := \
    $(ADB_COMMON_windows_CFLAGS) \

LIBADB_darwin_SRC_FILES := \
    get_my_path_darwin.cpp \
    sysdeps_unix.cpp \
    usb_osx.cpp \

LIBADB_linux_SRC_FILES := \
    get_my_path_linux.cpp \
    sysdeps_unix.cpp \
    usb_linux.cpp \

LIBADB_windows_SRC_FILES := \
    sysdeps_win32.cpp \
    sysdeps/win32/stat.cpp \
    usb_windows.cpp \

LIBADB_TEST_windows_SRCS := \
    sysdeps_win32_test.cpp \

include $(CLEAR_VARS)
LOCAL_CLANG := true
LOCAL_MODULE := libadbd
LOCAL_CFLAGS := $(LIBADB_CFLAGS) -DADB_HOST=0
LOCAL_SRC_FILES := \
    $(LIBADB_SRC_FILES) \
    adb_auth_client.cpp \
    jdwp_service.cpp \
    usb_linux_client.cpp \

LOCAL_SANITIZE := $(adb_target_sanitize)

# Even though we're building a static library (and thus there's no link step for
# this to take effect), this adds the includes to our path.
LOCAL_STATIC_LIBRARIES := libbase

include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := libadb
LOCAL_MODULE_HOST_OS := darwin linux windows
LOCAL_CFLAGS := $(LIBADB_CFLAGS) -DADB_HOST=1
LOCAL_CFLAGS_windows := $(LIBADB_windows_CFLAGS)
LOCAL_CFLAGS_linux := $(LIBADB_linux_CFLAGS)
LOCAL_CFLAGS_darwin := $(LIBADB_darwin_CFLAGS)
LOCAL_SRC_FILES := \
    $(LIBADB_SRC_FILES) \
    adb_auth_host.cpp \

LOCAL_SRC_FILES_darwin := $(LIBADB_darwin_SRC_FILES)
LOCAL_SRC_FILES_linux := $(LIBADB_linux_SRC_FILES)
LOCAL_SRC_FILES_windows := $(LIBADB_windows_SRC_FILES)

LOCAL_SANITIZE := $(adb_host_sanitize)

# Even though we're building a static library (and thus there's no link step for
# this to take effect), this adds the includes to our path.
LOCAL_STATIC_LIBRARIES := libcrypto_static libbase

LOCAL_C_INCLUDES_windows := development/host/windows/usb/api/
LOCAL_MULTILIB := first

include $(BUILD_HOST_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_CLANG := true
LOCAL_MODULE := adbd_test
LOCAL_CFLAGS := -DADB_HOST=0 $(LIBADB_CFLAGS)
LOCAL_SRC_FILES := \
    $(LIBADB_TEST_SRCS) \
    $(LIBADB_TEST_linux_SRCS) \
    shell_service.cpp \
    shell_service_protocol.cpp \
    shell_service_protocol_test.cpp \
    shell_service_test.cpp \

LOCAL_SANITIZE := $(adb_target_sanitize)
LOCAL_STATIC_LIBRARIES := libadbd
LOCAL_SHARED_LIBRARIES := liblog libbase libcutils
include $(BUILD_NATIVE_TEST)

# libdiagnose_usb
# =========================================================

include $(CLEAR_VARS)
LOCAL_MODULE := libdiagnose_usb
LOCAL_MODULE_HOST_OS := darwin linux windows
LOCAL_CFLAGS := $(LIBADB_CFLAGS)
LOCAL_SRC_FILES := diagnose_usb.cpp
# Even though we're building a static library (and thus there's no link step for
# this to take effect), this adds the includes to our path.
LOCAL_STATIC_LIBRARIES := libbase
include $(BUILD_HOST_STATIC_LIBRARY)

# adb_test
# =========================================================

include $(CLEAR_VARS)
LOCAL_MODULE := adb_test
LOCAL_MODULE_HOST_OS := darwin linux windows
LOCAL_CFLAGS := -DADB_HOST=1 $(LIBADB_CFLAGS)
LOCAL_CFLAGS_windows := $(LIBADB_windows_CFLAGS)
LOCAL_CFLAGS_linux := $(LIBADB_linux_CFLAGS)
LOCAL_CFLAGS_darwin := $(LIBADB_darwin_CFLAGS)
LOCAL_SRC_FILES := \
    $(LIBADB_TEST_SRCS) \
    adb_client.cpp \
    bugreport.cpp \
    bugreport_test.cpp \
    line_printer.cpp \
    services.cpp \
    shell_service_protocol.cpp \
    shell_service_protocol_test.cpp \

LOCAL_SRC_FILES_linux := $(LIBADB_TEST_linux_SRCS)
LOCAL_SRC_FILES_darwin := $(LIBADB_TEST_darwin_SRCS)
LOCAL_SRC_FILES_windows := $(LIBADB_TEST_windows_SRCS)
LOCAL_SANITIZE := $(adb_host_sanitize)
LOCAL_SHARED_LIBRARIES := libbase
LOCAL_STATIC_LIBRARIES := \
    libadb \
    libcrypto_static \
    libcutils \
    libdiagnose_usb \
    libgmock_host \

# Set entrypoint to wmain from sysdeps_win32.cpp instead of main
LOCAL_LDFLAGS_windows := -municode
LOCAL_LDLIBS_linux := -lrt -ldl -lpthread
LOCAL_LDLIBS_darwin := -framework CoreFoundation -framework IOKit
LOCAL_LDLIBS_windows := -lws2_32 -luserenv
LOCAL_STATIC_LIBRARIES_windows := AdbWinApi

LOCAL_MULTILIB := first

include $(BUILD_HOST_NATIVE_TEST)

# adb device tracker (used by ddms) test tool
# =========================================================

ifeq ($(HOST_OS),linux)
include $(CLEAR_VARS)
LOCAL_MODULE := adb_device_tracker_test
LOCAL_CFLAGS := -DADB_HOST=1 $(LIBADB_CFLAGS)
LOCAL_CFLAGS_windows := $(LIBADB_windows_CFLAGS)
LOCAL_CFLAGS_linux := $(LIBADB_linux_CFLAGS)
LOCAL_CFLAGS_darwin := $(LIBADB_darwin_CFLAGS)
LOCAL_SRC_FILES := test_track_devices.cpp
LOCAL_SANITIZE := $(adb_host_sanitize)
LOCAL_SHARED_LIBRARIES := libbase
LOCAL_STATIC_LIBRARIES := libadb libcrypto_static libcutils
LOCAL_LDLIBS += -lrt -ldl -lpthread
include $(BUILD_HOST_EXECUTABLE)
endif

# adb host tool
# =========================================================
include $(CLEAR_VARS)

LOCAL_LDLIBS_linux := -lrt -ldl -lpthread

LOCAL_LDLIBS_darwin := -lpthread -framework CoreFoundation -framework IOKit -framework Carbon

# Use wmain instead of main
LOCAL_LDFLAGS_windows := -municode
LOCAL_LDLIBS_windows := -lws2_32 -lgdi32
LOCAL_STATIC_LIBRARIES_windows := AdbWinApi
LOCAL_REQUIRED_MODULES_windows := AdbWinApi AdbWinUsbApi

LOCAL_SRC_FILES := \
    adb_client.cpp \
    bugreport.cpp \
    client/main.cpp \
    console.cpp \
    commandline.cpp \
    file_sync_client.cpp \
    line_printer.cpp \
    services.cpp \
    shell_service_protocol.cpp \

LOCAL_CFLAGS += \
    $(ADB_COMMON_CFLAGS) \
    -D_GNU_SOURCE \
    -DADB_HOST=1 \

LOCAL_CFLAGS_windows := \
    $(ADB_COMMON_windows_CFLAGS)

LOCAL_CFLAGS_linux := \
    $(ADB_COMMON_linux_CFLAGS) \

LOCAL_CFLAGS_darwin := \
    $(ADB_COMMON_darwin_CFLAGS) \
    -Wno-sizeof-pointer-memaccess -Wno-unused-parameter \

LOCAL_MODULE := adb
LOCAL_MODULE_TAGS := debug
LOCAL_MODULE_HOST_OS := darwin linux windows

LOCAL_SANITIZE := $(adb_host_sanitize)
LOCAL_STATIC_LIBRARIES := \
    libadb \
    libbase \
    libcrypto_static \
    libdiagnose_usb \
    liblog \

# Don't use libcutils on Windows.
LOCAL_STATIC_LIBRARIES_darwin := libcutils
LOCAL_STATIC_LIBRARIES_linux := libcutils

LOCAL_CXX_STL := libc++_static

# Don't add anything here, we don't want additional shared dependencies
# on the host adb tool, and shared libraries that link against libc++
# will violate ODR
LOCAL_SHARED_LIBRARIES :=

include $(BUILD_HOST_EXECUTABLE)

$(call dist-for-goals,dist_files sdk win_sdk,$(LOCAL_BUILT_MODULE))
ifdef HOST_CROSS_OS
# Archive adb.exe for win_sdk build.
$(call dist-for-goals,win_sdk,$(ALL_MODULES.host_cross_adb.BUILT))
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
    shell_service.cpp \
    shell_service_protocol.cpp \

LOCAL_CFLAGS := \
    $(ADB_COMMON_CFLAGS) \
    $(ADB_COMMON_linux_CFLAGS) \
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

LOCAL_SANITIZE := $(adb_target_sanitize)
LOCAL_STATIC_LIBRARIES := \
    libadbd \
    libbase \
    libfs_mgr \
    libfec \
    libfec_rs \
    libselinux \
    liblog \
    libmincrypt \
    libext4_utils_static \
    libsquashfs_utils \
    libcutils \
    libbase \
    libcrypto_static \
    libminijail

include $(BUILD_EXECUTABLE)

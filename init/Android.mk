# Copyright 2005 The Android Open Source Project

LOCAL_PATH:= $(call my-dir)

# --

ifneq (,$(filter userdebug eng,$(TARGET_BUILD_VARIANT)))
init_options += \
    -DALLOW_LOCAL_PROP_OVERRIDE=1 \
    -DALLOW_PERMISSIVE_SELINUX=1 \
    -DREBOOT_BOOTLOADER_ON_PANIC=1 \
    -DWORLD_WRITABLE_KMSG=1 \
    -DDUMP_ON_UMOUNT_FAILURE=1
else
init_options += \
    -DALLOW_LOCAL_PROP_OVERRIDE=0 \
    -DALLOW_PERMISSIVE_SELINUX=0 \
    -DREBOOT_BOOTLOADER_ON_PANIC=0 \
    -DWORLD_WRITABLE_KMSG=0 \
    -DDUMP_ON_UMOUNT_FAILURE=0
endif

ifneq (,$(filter eng,$(TARGET_BUILD_VARIANT)))
init_options += \
    -DSHUTDOWN_ZERO_TIMEOUT=1
else
init_options += \
    -DSHUTDOWN_ZERO_TIMEOUT=0
endif

init_options += -DLOG_UEVENTS=0

init_cflags += \
    $(init_options) \
    -Wall -Wextra \
    -Wno-unused-parameter \
    -Werror \
    -std=gnu++1z \

# --

include $(CLEAR_VARS)
LOCAL_CPPFLAGS := $(init_cflags)
LOCAL_SRC_FILES := main.cpp

LOCAL_MODULE:= init

LOCAL_MODULE_PATH := $(TARGET_ROOT_OUT)
LOCAL_UNSTRIPPED_PATH := $(TARGET_ROOT_OUT_UNSTRIPPED)

LOCAL_STATIC_LIBRARIES := \
    libinit \
    libbootloader_message \
    libfs_mgr \
    libfec \
    libfec_rs \
    libhidl-gen-utils \
    libsquashfs_utils \
    liblogwrap \
    libext4_utils \
    libseccomp_policy \
    libcrypto_utils \
    libsparse \
    libselinux \
    libprocessgroup \
    libavb \
    libkeyutils \
    libprotobuf-cpp-lite \
    libpropertyinfoserializer \
    libpropertyinfoparser \

shared_libs := \
    libcutils \
    libbase \
    liblog \
    libcrypto \
    libdl \
    libz \

ifneq ($(BOARD_BUILD_SYSTEM_ROOT_IMAGE),true)
# init is static executable for non-system-as-root devices, because the dynamic linker
# and shared libs are not available before /system is mounted, but init has to run
# before the partition is mounted.
LOCAL_STATIC_LIBRARIES += $(shared_libs) libc++_static
LOCAL_FORCE_STATIC_EXECUTABLE := true
else
LOCAL_SHARED_LIBRARIES := $(shared_libs) libc++
endif
shared_libs :=

LOCAL_REQUIRED_MODULES := \
    e2fsdroid \
    mke2fs \
    sload_f2fs \
    make_f2fs \

# Create symlinks.
LOCAL_POST_INSTALL_CMD := $(hide) mkdir -p $(TARGET_ROOT_OUT)/sbin; \
    ln -sf ../init $(TARGET_ROOT_OUT)/sbin/ueventd; \
    ln -sf ../init $(TARGET_ROOT_OUT)/sbin/watchdogd

LOCAL_SANITIZE := signed-integer-overflow
include $(BUILD_EXECUTABLE)

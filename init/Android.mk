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
LOCAL_SRC_FILES := \
    devices.cpp \
    first_stage_mount.cpp \
    init_first_stage.cpp \
    reboot_utils.cpp \
    selinux.cpp \
    switch_root.cpp \
    uevent_listener.cpp \
    util.cpp \

LOCAL_MODULE := init

LOCAL_FORCE_STATIC_EXECUTABLE := true

LOCAL_MODULE_PATH := $(TARGET_RAMDISK_OUT)
LOCAL_UNSTRIPPED_PATH := $(TARGET_RAMDISK_OUT_UNSTRIPPED)

# Set up the same mount points on the ramdisk that system-as-root contains.
LOCAL_POST_INSTALL_CMD := \
    mkdir -p $(TARGET_RAMDISK_OUT)/dev \
    mkdir -p $(TARGET_RAMDISK_OUT)/mnt \
    mkdir -p $(TARGET_RAMDISK_OUT)/proc \
    mkdir -p $(TARGET_RAMDISK_OUT)/sys \

LOCAL_STATIC_LIBRARIES := \
    libfs_mgr \
    libfec \
    libfec_rs \
    libsquashfs_utils \
    liblogwrap \
    libext4_utils \
    libseccomp_policy \
    libcrypto_utils \
    libsparse \
    libavb \
    libkeyutils \
    liblp \
    libcutils \
    libbase \
    liblog \
    libcrypto \
    libdl \
    libz \
    libselinux \
    libcap \

LOCAL_REQUIRED_MODULES := \
    init_second_stage \

LOCAL_SANITIZE := signed-integer-overflow
include $(BUILD_EXECUTABLE)

# Copyright 2005 The Android Open Source Project

LOCAL_PATH:= $(call my-dir)

-include system/sepolicy/policy_version.mk

# --

ifneq (,$(filter userdebug eng,$(TARGET_BUILD_VARIANT)))
init_options += \
    -DALLOW_FIRST_STAGE_CONSOLE=1 \
    -DALLOW_LOCAL_PROP_OVERRIDE=1 \
    -DALLOW_PERMISSIVE_SELINUX=1 \
    -DREBOOT_BOOTLOADER_ON_PANIC=1 \
    -DWORLD_WRITABLE_KMSG=1 \
    -DDUMP_ON_UMOUNT_FAILURE=1
else
init_options += \
    -DALLOW_FIRST_STAGE_CONSOLE=0 \
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

init_options += -DLOG_UEVENTS=0 \
    -DSEPOLICY_VERSION=$(POLICYVERS)

init_cflags += \
    $(init_options) \
    -Wall -Wextra \
    -Wno-unused-parameter \
    -Werror \

# --

# Do not build this even with mmma if we're system-as-root, otherwise it will overwrite the symlink.
ifneq ($(BOARD_BUILD_SYSTEM_ROOT_IMAGE),true)
include $(CLEAR_VARS)
LOCAL_CPPFLAGS := $(init_cflags)
LOCAL_SRC_FILES := \
    block_dev_initializer.cpp \
    devices.cpp \
    first_stage_console.cpp \
    first_stage_init.cpp \
    first_stage_main.cpp \
    first_stage_mount.cpp \
    reboot_utils.cpp \
    selabel.cpp \
    selinux.cpp \
    switch_root.cpp \
    uevent_listener.cpp \
    util.cpp \

LOCAL_MODULE := init_first_stage
LOCAL_MODULE_STEM := init

LOCAL_FORCE_STATIC_EXECUTABLE := true

LOCAL_MODULE_PATH := $(TARGET_RAMDISK_OUT)
LOCAL_UNSTRIPPED_PATH := $(TARGET_RAMDISK_OUT_UNSTRIPPED)

# Install adb_debug.prop into debug ramdisk.
# This allows adb root on a user build, when debug ramdisk is used.
LOCAL_REQUIRED_MODULES := \
   adb_debug.prop \

# Set up the directories that first stage init mounts on.
LOCAL_POST_INSTALL_CMD := mkdir -p \
    $(TARGET_RAMDISK_OUT)/debug_ramdisk \
    $(TARGET_RAMDISK_OUT)/dev \
    $(TARGET_RAMDISK_OUT)/mnt \
    $(TARGET_RAMDISK_OUT)/proc \
    $(TARGET_RAMDISK_OUT)/sys \

LOCAL_STATIC_LIBRARIES := \
    libc++fs \
    libfs_avb \
    libfs_mgr \
    libfec \
    libfec_rs \
    libsquashfs_utils \
    liblogwrap \
    libext4_utils \
    libcrypto_utils \
    libsparse \
    libavb \
    libkeyutils \
    liblp \
    libcutils \
    libbase \
    liblog \
    libcrypto_static \
    libdl \
    libz \
    libselinux \
    libcap \
    libgsi \
    libcom.android.sysprop.apex \
    liblzma \
    libunwindstack_no_dex \
    libbacktrace_no_dex \
    libmodprobe \
    libext2_uuid \
    libprotobuf-cpp-lite \
    libsnapshot_init \

LOCAL_SANITIZE := signed-integer-overflow
# First stage init is weird: it may start without stdout/stderr, and no /proc.
LOCAL_NOSANITIZE := hwaddress
include $(BUILD_EXECUTABLE)
endif

include $(CLEAR_VARS)

LOCAL_MODULE := init_system
LOCAL_REQUIRED_MODULES := \
   init_second_stage \

include $(BUILD_PHONY_PACKAGE)

include $(CLEAR_VARS)

LOCAL_MODULE := init_vendor
ifneq ($(BOARD_BUILD_SYSTEM_ROOT_IMAGE),true)
LOCAL_REQUIRED_MODULES := \
   init_first_stage \

endif
include $(BUILD_PHONY_PACKAGE)

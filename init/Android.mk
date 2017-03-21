# Copyright 2005 The Android Open Source Project

LOCAL_PATH:= $(call my-dir)

# --

ifneq (,$(filter userdebug eng,$(TARGET_BUILD_VARIANT)))
init_options += \
    -DALLOW_LOCAL_PROP_OVERRIDE=1 \
    -DALLOW_PERMISSIVE_SELINUX=1 \
    -DREBOOT_BOOTLOADER_ON_PANIC=1
else
init_options += \
    -DALLOW_LOCAL_PROP_OVERRIDE=0 \
    -DALLOW_PERMISSIVE_SELINUX=0 \
    -DREBOOT_BOOTLOADER_ON_PANIC=0
endif

init_options += -DLOG_UEVENTS=0

init_cflags += \
    $(init_options) \
    -Wall -Wextra \
    -Wno-unused-parameter \
    -Werror \
    -std=gnu++1z \

# --

# If building on Linux, then build unit test for the host.
ifeq ($(HOST_OS),linux)
include $(CLEAR_VARS)
LOCAL_CPPFLAGS := $(init_cflags)
LOCAL_SRC_FILES:= \
    parser/tokenizer.cpp \

LOCAL_MODULE := libinit_parser
LOCAL_CLANG := true
include $(BUILD_HOST_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := init_parser_tests
LOCAL_SRC_FILES := \
    parser/tokenizer_test.cpp \

LOCAL_STATIC_LIBRARIES := libinit_parser
LOCAL_CLANG := true
include $(BUILD_HOST_NATIVE_TEST)
endif

include $(CLEAR_VARS)
LOCAL_CPPFLAGS := $(init_cflags)
LOCAL_SRC_FILES:= \
    action.cpp \
    capabilities.cpp \
    descriptors.cpp \
    import_parser.cpp \
    init_parser.cpp \
    log.cpp \
    parser.cpp \
    service.cpp \
    util.cpp \

LOCAL_STATIC_LIBRARIES := libbase libselinux liblog libprocessgroup libnl
LOCAL_WHOLE_STATIC_LIBRARIES := libcap
LOCAL_MODULE := libinit
LOCAL_SANITIZE := integer
LOCAL_CLANG := true
include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_CPPFLAGS := $(init_cflags)
LOCAL_SRC_FILES:= \
    bootchart.cpp \
    builtins.cpp \
    devices.cpp \
    init.cpp \
    keychords.cpp \
    property_service.cpp \
    signal_handler.cpp \
    ueventd.cpp \
    ueventd_parser.cpp \
    watchdogd.cpp \

LOCAL_MODULE:= init
LOCAL_C_INCLUDES += \
    system/core/mkbootimg

LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_MODULE_PATH := $(TARGET_ROOT_OUT)
LOCAL_UNSTRIPPED_PATH := $(TARGET_ROOT_OUT_UNSTRIPPED)

LOCAL_STATIC_LIBRARIES := \
    libinit \
    libbootloader_message \
    libfs_mgr \
    libfec \
    libfec_rs \
    libsquashfs_utils \
    liblogwrap \
    libcutils \
    libext4_utils \
    libbase \
    libc \
    libselinux \
    liblog \
    libcrypto_utils \
    libcrypto \
    libc++_static \
    libdl \
    libsparse \
    libz \
    libprocessgroup \
    libnl \
    libavb

# Include SELinux policy. We do this here because different modules
# need to be included based on the value of PRODUCT_FULL_TREBLE. This
# type of conditional inclusion cannot be done in top-level files such
# as build/target/product/embedded.mk.
# This conditional inclusion closely mimics the conditional logic
# inside init/init.cpp for loading SELinux policy from files.
ifeq ($(PRODUCT_FULL_TREBLE),true)
# Use split SELinux policy
LOCAL_REQUIRED_MODULES += \
    mapping_sepolicy.cil \
    nonplat_sepolicy.cil \
    plat_sepolicy.cil \
    plat_sepolicy.cil.sha256 \
    secilc \
    nonplat_file_contexts \
    plat_file_contexts

# Include precompiled policy, unless told otherwise
ifneq ($(PRODUCT_PRECOMPILED_SEPOLICY),false)
LOCAL_REQUIRED_MODULES += precompiled_sepolicy precompiled_sepolicy.plat.sha256
endif

else
# Use monolithic SELinux policy
LOCAL_REQUIRED_MODULES += sepolicy \
    file_contexts.bin
endif

# Create symlinks.
LOCAL_POST_INSTALL_CMD := $(hide) mkdir -p $(TARGET_ROOT_OUT)/sbin; \
    ln -sf ../init $(TARGET_ROOT_OUT)/sbin/ueventd; \
    ln -sf ../init $(TARGET_ROOT_OUT)/sbin/watchdogd

LOCAL_SANITIZE := integer
LOCAL_CLANG := true
include $(BUILD_EXECUTABLE)


# Unit tests.
# =========================================================
include $(CLEAR_VARS)
LOCAL_MODULE := init_tests
LOCAL_SRC_FILES := \
    init_parser_test.cpp \
    property_service_test.cpp \
    util_test.cpp \

LOCAL_SHARED_LIBRARIES += \
    libcutils \
    libbase \

LOCAL_STATIC_LIBRARIES := libinit
LOCAL_SANITIZE := integer
LOCAL_CLANG := true
LOCAL_CPPFLAGS := -Wall -Wextra -Werror
include $(BUILD_NATIVE_TEST)


# Include targets in subdirs.
# =========================================================
include $(call all-makefiles-under,$(LOCAL_PATH))

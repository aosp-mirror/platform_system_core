# Copyright 2011 The Android Open Source Project

LOCAL_PATH:= $(call my-dir)

common_static_libraries := \
    liblogwrap \
    libfec \
    libfec_rs \
    libbase \
    libmincrypt \
    libcrypto_static \
    libext4_utils_static \
    libsquashfs_utils

include $(CLEAR_VARS)
LOCAL_CLANG := true
LOCAL_SANITIZE := integer
LOCAL_SRC_FILES:= \
    fs_mgr.c \
    fs_mgr_format.c \
    fs_mgr_fstab.c \
    fs_mgr_slotselect.c \
    fs_mgr_verity.cpp
LOCAL_C_INCLUDES := \
    $(LOCAL_PATH)/include \
    system/vold \
    system/extras/ext4_utils \
    external/openssl/include \
    bootable/recovery
LOCAL_MODULE:= libfs_mgr
LOCAL_STATIC_LIBRARIES := $(common_static_libraries)
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/include
LOCAL_CFLAGS := -Werror
ifneq (,$(filter userdebug,$(TARGET_BUILD_VARIANT)))
LOCAL_CFLAGS += -DALLOW_ADBD_DISABLE_VERITY=1
endif
include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_CLANG := true
LOCAL_SANITIZE := integer
LOCAL_SRC_FILES:= fs_mgr_main.c
LOCAL_C_INCLUDES := $(LOCAL_PATH)/include
LOCAL_MODULE:= fs_mgr
LOCAL_MODULE_TAGS := optional
LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_MODULE_PATH := $(TARGET_ROOT_OUT)/sbin
LOCAL_UNSTRIPPED_PATH := $(TARGET_ROOT_OUT_UNSTRIPPED)
LOCAL_STATIC_LIBRARIES := libfs_mgr \
    $(common_static_libraries) \
    libcutils \
    liblog \
    libc \
    libsparse_static \
    libz \
    libselinux
LOCAL_CXX_STL := libc++_static
LOCAL_CFLAGS := -Werror
include $(BUILD_EXECUTABLE)

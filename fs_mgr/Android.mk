# Copyright 2011 The Android Open Source Project

LOCAL_PATH:= $(call my-dir)

common_static_libraries := \
    liblogwrap \
    libfec \
    libfec_rs \
    libbase \
    libcrypto_utils \
    libcrypto \
    libext4_utils \
    libsquashfs_utils \
    libselinux \
    libavb

include $(CLEAR_VARS)
LOCAL_SANITIZE := integer
LOCAL_SRC_FILES:= fs_mgr_main.cpp
LOCAL_C_INCLUDES := $(LOCAL_PATH)/include
LOCAL_MODULE:= fs_mgr
LOCAL_MODULE_TAGS := optional
LOCAL_REQUIRED_MODULES := mke2fs mke2fs.conf e2fsdroid
LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_MODULE_PATH := $(TARGET_ROOT_OUT)/sbin
LOCAL_UNSTRIPPED_PATH := $(TARGET_ROOT_OUT_UNSTRIPPED)
LOCAL_STATIC_LIBRARIES := libfs_mgr \
    $(common_static_libraries) \
    libcutils \
    liblog \
    libc \
    libsparse \
    libz \
    libselinux
LOCAL_CXX_STL := libc++_static
LOCAL_CFLAGS := -Werror
include $(BUILD_EXECUTABLE)

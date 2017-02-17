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
LOCAL_CLANG := true
LOCAL_SANITIZE := integer
LOCAL_SRC_FILES:= \
    fs_mgr.cpp \
    fs_mgr_dm_ioctl.cpp \
    fs_mgr_format.cpp \
    fs_mgr_fstab.cpp \
    fs_mgr_slotselect.cpp \
    fs_mgr_verity.cpp \
    fs_mgr_avb.cpp \
    fs_mgr_avb_ops.cpp \
    fs_mgr_boot_config.cpp
LOCAL_C_INCLUDES := \
    $(LOCAL_PATH)/include \
    system/vold \
    system/extras/ext4_utils
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
LOCAL_SRC_FILES:= fs_mgr_main.cpp
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
    libsparse \
    libz \
    libselinux
LOCAL_CXX_STL := libc++_static
LOCAL_CFLAGS := -Werror
include $(BUILD_EXECUTABLE)

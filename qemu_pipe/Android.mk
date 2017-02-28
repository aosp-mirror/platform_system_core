# Copyright 2011 The Android Open Source Project

LOCAL_PATH:= $(call my-dir)

common_static_libraries := \
    libbase
include $(CLEAR_VARS)
LOCAL_CLANG := true
LOCAL_SANITIZE := integer
LOCAL_SRC_FILES:= \
    qemu_pipe.cpp
LOCAL_C_INCLUDES := \
    $(LOCAL_PATH)/include \
    system/base/include
LOCAL_MODULE:= libqemu_pipe
LOCAL_STATIC_LIBRARIES := $(common_static_libraries)
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/include
LOCAL_CFLAGS := -Werror
include $(BUILD_STATIC_LIBRARY)

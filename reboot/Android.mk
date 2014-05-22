# Copyright 2013 The Android Open Source Project

LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES := reboot.c

LOCAL_SHARED_LIBRARIES := libcutils

LOCAL_MODULE := reboot

LOCAL_CFLAGS := -Werror

include $(BUILD_EXECUTABLE)

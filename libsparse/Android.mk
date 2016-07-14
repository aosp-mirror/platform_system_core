# Copyright 2010 The Android Open Source Project

LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := simg_dump.py
LOCAL_SRC_FILES := simg_dump.py
LOCAL_MODULE_CLASS := EXECUTABLES
LOCAL_IS_HOST_MODULE := true
LOCAL_CFLAGS := -Werror
include $(BUILD_PREBUILT)

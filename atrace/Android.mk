# Copyright 2012 The Android Open Source Project

LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES:= atrace.c

LOCAL_MODULE:= atrace

LOCAL_MODULE_TAGS:= optional

include $(BUILD_EXECUTABLE)

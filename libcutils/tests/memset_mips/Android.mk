# Copyright 2012 The Android Open Source Project

ifeq ($(TARGET_ARCH),mips)

LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
	test_memset.c \
	android_memset_dumb.S \
	android_memset_test.S \
	memset_cmips.S \
	memset_omips.S

LOCAL_MODULE:= test_memset

LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_STATIC_LIBRARIES := libcutils libc
LOCAL_MODULE_TAGS := tests

include $(BUILD_EXECUTABLE)

endif

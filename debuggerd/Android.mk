# Copyright 2005 The Android Open Source Project

ifeq ($(TARGET_ARCH),arm)

LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES:= debuggerd.c getevent.c unwind-arm.c pr-support.c utility.c
LOCAL_CFLAGS := -Wall
LOCAL_MODULE := debuggerd

LOCAL_STATIC_LIBRARIES := libcutils libc

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := crasher.c
LOCAL_SRC_FILES += crashglue.S
LOCAL_MODULE := crasher
LOCAL_MODULE_PATH := $(TARGET_OUT_OPTIONAL_EXECUTABLES)
LOCAL_MODULE_TAGS := eng
#LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_SHARED_LIBRARIES := libcutils libc
include $(BUILD_EXECUTABLE)

ifeq ($(TARGET_ARCH_VARIANT),armv7-a)
include $(CLEAR_VARS)
LOCAL_SRC_FILES := vfp-crasher.c vfp.S
LOCAL_MODULE := vfp-crasher
LOCAL_MODULE_PATH := $(TARGET_OUT_OPTIONAL_EXECUTABLES)
LOCAL_MODULE_TAGS := eng
LOCAL_SHARED_LIBRARIES := libcutils libc
include $(BUILD_EXECUTABLE)
endif # TARGET_ARCH_VARIANT == armv7-a

endif # TARGET_ARCH == arm

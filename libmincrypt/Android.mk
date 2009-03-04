# Copyright 2008 The Android Open Source Project
#
LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_MODULE := libmincrypt
LOCAL_SRC_FILES := rsa.c sha.c
include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)

LOCAL_MODULE := libmincrypt
LOCAL_SRC_FILES := rsa.c sha.c
include $(BUILD_HOST_STATIC_LIBRARY)


# TODO: drop the hyphen once these are checked in
include $(LOCAL_PATH)/tools/Android.mk

# Copyright 2016 The Android Open Source Project

LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
    AnimationParser_test.cpp \

LOCAL_MODULE := healthd_test
LOCAL_MODULE_TAGS := tests

LOCAL_STATIC_LIBRARIES := \
	libhealthd_internal \

LOCAL_SHARED_LIBRARIES := \
	liblog \
	libbase \
	libcutils \

include $(BUILD_NATIVE_TEST)

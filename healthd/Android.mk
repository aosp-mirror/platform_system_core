# Copyright 2013 The Android Open Source Project

ifneq ($(BUILD_TINY_ANDROID),true)

LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := healthd_board_default.cpp
LOCAL_MODULE := libhealthd.default
include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
	healthd.cpp \
	BatteryMonitor.cpp \
	BatteryPropertiesRegistrar.cpp

LOCAL_MODULE := healthd
LOCAL_MODULE_TAGS := optional
LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_MODULE_PATH := $(TARGET_ROOT_OUT_SBIN)
LOCAL_UNSTRIPPED_PATH := $(TARGET_ROOT_OUT_SBIN_UNSTRIPPED)

LOCAL_STATIC_LIBRARIES :=  libbatteryservice libbinder libz libutils libstdc++ libcutils liblog libm libc
LOCAL_HAL_STATIC_LIBRARIES := libhealthd

include $(BUILD_EXECUTABLE)

endif

# Copyright 2013 The Android Open Source Project

LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := memtrack.c
LOCAL_MODULE := libmemtrack
LOCAL_C_INCLUDES += hardware/libhardware/include
LOCAL_SHARED_LIBRARIES := libhardware liblog
LOCAL_CFLAGS := -Wall -Werror
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := memtrack_test.c
LOCAL_MODULE := memtrack_test
LOCAL_C_INCLUDES := $(call include-path-for, libpagemap)
LOCAL_SHARED_LIBRARIES := libmemtrack libpagemap
LOCAL_CFLAGS := -Wall -Werror
include $(BUILD_EXECUTABLE)

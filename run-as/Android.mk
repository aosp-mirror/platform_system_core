LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES := run-as.c package.c

LOCAL_SHARED_LIBRARIES := libselinux

LOCAL_MODULE := run-as

LOCAL_CFLAGS := -Werror

include $(BUILD_EXECUTABLE)

LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES := lmkd.c
LOCAL_STATIC_LIBRARIES := libcutils liblog libm libc
LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_CFLAGS := -Werror

LOCAL_MODULE := lmkd

include $(BUILD_EXECUTABLE)

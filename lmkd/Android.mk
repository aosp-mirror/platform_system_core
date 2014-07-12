LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES := lmkd.c
LOCAL_SHARED_LIBRARIES := liblog libm libc libprocessgroup
LOCAL_CFLAGS := -Werror

LOCAL_MODULE := lmkd

include $(BUILD_EXECUTABLE)

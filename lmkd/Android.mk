LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES := lmkd.c
LOCAL_SHARED_LIBRARIES := liblog libm libc libprocessgroup libcutils
LOCAL_CFLAGS := -Werror

LOCAL_MODULE := lmkd

LOCAL_INIT_RC := lmkd.rc

include $(BUILD_EXECUTABLE)

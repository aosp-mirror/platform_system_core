LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)
LOCAL_SRC_FILES:= netcfg.c
LOCAL_MODULE:= netcfg
LOCAL_SHARED_LIBRARIES := libnetutils
LOCAL_CFLAGS := -Werror
include $(BUILD_EXECUTABLE)

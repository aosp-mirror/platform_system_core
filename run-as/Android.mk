LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES:= run-as.c package.c

LOCAL_MODULE:= run-as

include $(BUILD_EXECUTABLE)

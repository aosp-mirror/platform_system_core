LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)
LOCAL_SRC_FILES:= logwrapper.c
LOCAL_MODULE := logwrapper
LOCAL_STATIC_LIBRARIES := liblog
include $(BUILD_EXECUTABLE)

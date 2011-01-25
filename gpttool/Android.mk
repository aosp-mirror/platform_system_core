ifeq ($(HOST_OS),linux)

LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES := gpttool.c
LOCAL_STATIC_LIBRARIES := libz

LOCAL_MODULE := gpttool
LOCAL_MODULE_TAGS := eng

include $(BUILD_HOST_EXECUTABLE)

endif

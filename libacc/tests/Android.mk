LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
	main.cpp

LOCAL_SHARED_LIBRARIES := \
    libacc

LOCAL_MODULE:= acc

LOCAL_MODULE_TAGS := tests

include $(BUILD_EXECUTABLE)


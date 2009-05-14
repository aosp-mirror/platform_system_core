LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

#
# Shared library
#

LOCAL_MODULE:= acc
LOCAL_SRC_FILES := acc.cpp

include $(BUILD_EXECUTABLE)

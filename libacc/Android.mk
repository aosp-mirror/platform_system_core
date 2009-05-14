LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

#
# Shared library
#

LOCAL_MODULE:= acc
LOCAL_SRC_FILES := acc.cpp disassem.cpp
LOCAL_MODULE_TAGS := tests

include $(BUILD_EXECUTABLE)

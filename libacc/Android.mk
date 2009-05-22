LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

#
# Shared library
#

LOCAL_MODULE:= libacc
LOCAL_SRC_FILES := acc.cpp

ifeq ($(TARGET_ARCH),arm)
LOCAL_SRC_FILES += disassem.cpp
endif

LOCAL_SHARED_LIBRARIES := libdl

include $(BUILD_SHARED_LIBRARY)

include $(call all-makefiles-under,$(LOCAL_PATH))
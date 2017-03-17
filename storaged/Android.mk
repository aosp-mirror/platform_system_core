# Copyright 2016 The Android Open Source Project

LOCAL_PATH := $(call my-dir)

LIBSTORAGED_SHARED_LIBRARIES := \
    libbinder \
    libbase \
    libutils \
    libcutils \
    liblog \
    libsysutils \
    libpackagelistparser \
    libbatteryservice \

include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
    storaged.cpp \
    storaged_info.cpp \
    storaged_service.cpp \
    storaged_utils.cpp \
    storaged_uid_monitor.cpp \
    EventLogTags.logtags

LOCAL_MODULE := libstoraged
LOCAL_CFLAGS := -Werror
LOCAL_C_INCLUDES := $(LOCAL_PATH)/include external/googletest/googletest/include
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/include
LOCAL_SHARED_LIBRARIES := $(LIBSTORAGED_SHARED_LIBRARIES)
include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)

LOCAL_MODULE := storaged
LOCAL_INIT_RC := storaged.rc
LOCAL_SRC_FILES := main.cpp
# libstoraged is an internal static library, only main.cpp and storaged_test.cpp should be using it
LOCAL_STATIC_LIBRARIES := libstoraged
LOCAL_SHARED_LIBRARIES := $(LIBSTORAGED_SHARED_LIBRARIES)
LOCAL_CFLAGS := -Wall -Werror -Wno-unused-parameter
LOCAL_C_INCLUDES := external/googletest/googletest/include

include $(BUILD_EXECUTABLE)

include $(call first-makefiles-under,$(LOCAL_PATH))

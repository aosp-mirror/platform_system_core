LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := sdcard.cpp fuse.cpp
LOCAL_MODULE := sdcard
LOCAL_CFLAGS := -Wall -Wno-unused-parameter -Werror
LOCAL_SHARED_LIBRARIES := libbase libcutils libminijail libpackagelistparser

LOCAL_SANITIZE := integer
LOCAL_CLANG := true

include $(BUILD_EXECUTABLE)

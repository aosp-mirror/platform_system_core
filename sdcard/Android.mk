LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES:= sdcard.c
LOCAL_MODULE:= sdcard

LOCAL_SHARED_LIBRARIES := libc

include $(BUILD_EXECUTABLE)

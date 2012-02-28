LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := ion.c
LOCAL_MODULE := libion
LOCAL_MODULE_TAGS := optional
LOCAL_SHARED_LIBRARIES := liblog
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := ion.c ion_test.c
LOCAL_MODULE := iontest
LOCAL_MODULE_TAGS := optional tests
LOCAL_SHARED_LIBRARIES := liblog
include $(BUILD_EXECUTABLE)

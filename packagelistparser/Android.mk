LOCAL_PATH:= $(call my-dir)

#########################
include $(CLEAR_VARS)

LOCAL_MODULE := libpackagelistparser
LOCAL_MODULE_TAGS := optional
LOCAL_SRC_FILES := packagelistparser.c
LOCAL_SHARED_LIBRARIES := liblog
LOCAL_C_INCLUDES := $(LOCAL_PATH)/include
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/include

LOCAL_CLANG := true
LOCAL_SANITIZE := integer

include $(BUILD_SHARED_LIBRARY)

#########################
include $(CLEAR_VARS)


LOCAL_MODULE := libpackagelistparser
LOCAL_MODULE_TAGS := optional
LOCAL_SRC_FILES := packagelistparser.c
LOCAL_STATIC_LIBRARIES := liblog
LOCAL_C_INCLUDES := $(LOCAL_PATH)/include
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/include

LOCAL_CLANG := true
LOCAL_SANITIZE := integer

include $(BUILD_STATIC_LIBRARY)

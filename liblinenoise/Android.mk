LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

# Static library
# ========================================================

include $(CLEAR_VARS)
LOCAL_MODULE:= liblinenoise
LOCAL_SRC_FILES := linenoise.c


include $(BUILD_STATIC_LIBRARY)
